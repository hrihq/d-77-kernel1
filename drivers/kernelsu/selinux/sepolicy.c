#include "ss/avtab.h"
#include "ss/constraint.h"
#include "ss/ebitmap.h"
#include "ss/hashtab.h"
#include "ss/policydb.h"
#include "ss/services.h"
#include <linux/gfp.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/vmalloc.h>

#include "sepolicy.h"
#include "klog.h" // IWYU pragma: keep
#include "ss/symtab.h"

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0))
// 4.14 selinux internal API incompatible (flex_array avtab, selinux_ss).
// sepolicy patching is a no-op; root still works.
int handle_sepolicy(void __user *user_data, u64 data_len) { return -EINVAL; }
void ksu_destroy_sepolicy(struct selinux_policy *orig) {}
struct selinux_policy *ksu_dup_sepolicy(struct selinux_policy *old_pol) { return NULL; }
#else
void *ksu_kvrealloc_compat(const void *p, size_t oldsize, size_t newsize,
                           gfp_t flags)
{
    void *newp;

    if (oldsize >= newsize)
        return (void *)p;
    newp = kvmalloc(newsize, flags);
    if (!newp)
        return NULL;
    memcpy(newp, p, oldsize);
    kvfree(p);
    return newp;
}
#define ksu_kvrealloc(p, new_size, old_size)                                   \
    ksu_kvrealloc_compat(p, old_size, new_size, GFP_KERNEL)

static bool add_type(struct policydb *db, const char *type_name, bool attr)
{
    struct type_datum *type = symtab_search(&db->p_types, type_name);
    if (type) {
        pr_warn("Type %s already exists\n", type_name);
        return true;
    }

    u32 value = ++db->p_types.nprim;
    type = (struct type_datum *)kzalloc(sizeof(struct type_datum), GFP_KERNEL);
    if (!type) {
        pr_err("add_type: alloc type_datum failed.\n");
        return false;
    }

    type->primary = 1;
    type->value = value;
    type->attribute = attr;

    char *key = kstrdup(type_name, GFP_KERNEL);
    if (!key) {
        pr_err("add_type: alloc key failed.\n");
        return false;
    }

    if (symtab_insert(&db->p_types, key, type)) {
        pr_err("add_type: insert symtab failed.\n");
        return false;
    }

    struct ebitmap *new_type_attr_map_array =
        ksu_kvrealloc(db->type_attr_map_array, value * sizeof(struct ebitmap),
                      (value - 1) * sizeof(struct ebitmap));

    if (!new_type_attr_map_array) {
        pr_err("add_type: alloc type_attr_map_array failed\n");
        return false;
    }

    struct type_datum **new_type_val_to_struct =
        ksu_kvrealloc(db->type_val_to_struct,
                      sizeof(*db->type_val_to_struct) * value,
                      sizeof(*db->type_val_to_struct) * (value - 1));

    if (!new_type_val_to_struct) {
        pr_err("add_type: alloc type_val_to_struct failed\n");
        return false;
    }

    char **new_val_to_name_types =
        ksu_kvrealloc(db->sym_val_to_name[SYM_TYPES], sizeof(char *) * value,
                      sizeof(char *) * (value - 1));
    if (!new_val_to_name_types) {
        pr_err("add_type: alloc val_to_name failed\n");
        return false;
    }

    db->type_attr_map_array = new_type_attr_map_array;
    ebitmap_init(&db->type_attr_map_array[value - 1]);
    ebitmap_set_bit(&db->type_attr_map_array[value - 1], value - 1, 1);

    db->type_val_to_struct = new_type_val_to_struct;
    db->type_val_to_struct[value - 1] = type;

    db->sym_val_to_name[SYM_TYPES] = new_val_to_name_types;
    db->sym_val_to_name[SYM_TYPES][value - 1] = key;

    int i;
    for (i = 0; i < db->p_roles.nprim; ++i) {
        ebitmap_set_bit(&db->role_val_to_struct[i]->types, value - 1, 1);
    }

    return true;
}

static bool set_type_state(struct policydb *db, const char *type_name,
                           bool permissive)
{
    struct type_datum *type;
    if (type_name == NULL) {
        struct hashtab_node *node;
        ksu_hashtab_for_each(db->p_types.table, node)
        {
            type = (struct type_datum *)(node->datum);
            if (ebitmap_set_bit(&db->permissive_map, type->value, permissive))
                pr_info("Could not set bit in permissive map\n");
        };
    } else {
        type = (struct type_datum *)symtab_search(&db->p_types, type_name);
        if (type == NULL) {
            pr_info("type %s does not exist\n", type_name);
            return false;
        }
        if (ebitmap_set_bit(&db->permissive_map, type->value, permissive)) {
            pr_info("Could not set bit in permissive map\n");
            return false;
        }
    }
    return true;
}

static void add_typeattribute_raw(struct policydb *db, struct type_datum *type,
                                  struct type_datum *attr)
{
    struct ebitmap *sattr = &db->type_attr_map_array[type->value - 1];
    ebitmap_set_bit(sattr, attr->value - 1, 1);

    struct hashtab_node *node;
    struct constraint_node *n;
    struct constraint_expr *e;
    ksu_hashtab_for_each(db->p_classes.table, node)
    {
        struct class_datum *cls = (struct class_datum *)(node->datum);
        for (n = cls->constraints; n; n = n->next) {
            for (e = n->expr; e; e = e->next) {
                if (e->expr_type == CEXPR_NAMES &&
                    ebitmap_get_bit(&e->type_names->types, attr->value - 1)) {
                    ebitmap_set_bit(&e->names, type->value - 1, 1);
                }
            }
        }
    };
}

static bool add_typeattribute(struct policydb *db, const char *type,
                              const char *attr)
{
    struct type_datum *type_d = symtab_search(&db->p_types, type);
    if (type_d == NULL) {
        pr_info("type %s does not exist\n", type);
        return false;
    } else if (type_d->attribute) {
        pr_info("type %s is an attribute\n", attr);
        return false;
    }

    struct type_datum *attr_d = symtab_search(&db->p_types, attr);
    if (attr_d == NULL) {
        pr_info("attribute %s does not exist\n", type);
        return false;
    } else if (!attr_d->attribute) {
        pr_info("type %s is not an attribute \n", attr);
        return false;
    }

    add_typeattribute_raw(db, type_d, attr_d);
    return true;
}

//////////////////////////////////////////////////////////////////////////

// Operation on types
bool ksu_type(struct policydb *db, const char *name, const char *attr)
{
    return add_type(db, name, false) && add_typeattribute(db, name, attr);
}

bool ksu_attribute(struct policydb *db, const char *name)
{
    return add_type(db, name, true);
}

bool ksu_permissive(struct policydb *db, const char *type)
{
    return set_type_state(db, type, true);
}

bool ksu_enforce(struct policydb *db, const char *type)
{
    return set_type_state(db, type, false);
}

bool ksu_typeattribute(struct policydb *db, const char *type, const char *attr)
{
    return add_typeattribute(db, type, attr);
}

bool ksu_exists(struct policydb *db, const char *type)
{
    return symtab_search(&db->p_types, type) != NULL;
}

// Access vector rules
bool ksu_allow(struct policydb *db, const char *src, const char *tgt,
               const char *cls, const char *perm)
{
    return add_rule(db, src, tgt, cls, perm, AVTAB_ALLOWED, false);
}

bool ksu_deny(struct policydb *db, const char *src, const char *tgt,
              const char *cls, const char *perm)
{
    return add_rule(db, src, tgt, cls, perm, AVTAB_ALLOWED, true);
}

bool ksu_auditallow(struct policydb *db, const char *src, const char *tgt,
                    const char *cls, const char *perm)
{
    return add_rule(db, src, tgt, cls, perm, AVTAB_AUDITALLOW, false);
}
bool ksu_dontaudit(struct policydb *db, const char *src, const char *tgt,
                   const char *cls, const char *perm)
{
    return add_rule(db, src, tgt, cls, perm, AVTAB_AUDITDENY, true);
}

// Extended permissions access vector rules
bool ksu_allowxperm(struct policydb *db, const char *src, const char *tgt,
                    const char *cls, const char *range)
{
    return add_xperm_rule(db, src, tgt, cls, range, AVTAB_XPERMS_ALLOWED,
                          false);
}

bool ksu_auditallowxperm(struct policydb *db, const char *src, const char *tgt,
                         const char *cls, const char *range)
{
    return add_xperm_rule(db, src, tgt, cls, range, AVTAB_XPERMS_AUDITALLOW,
                          false);
}

bool ksu_dontauditxperm(struct policydb *db, const char *src, const char *tgt,
                        const char *cls, const char *range)
{
    return add_xperm_rule(db, src, tgt, cls, range, AVTAB_XPERMS_DONTAUDIT,
                          false);
}

// Type rules
bool ksu_type_transition(struct policydb *db, const char *src, const char *tgt,
                         const char *cls, const char *def, const char *obj)
{
    if (obj) {
        return add_filename_trans(db, src, tgt, cls, def, obj);
    } else {
        return add_type_rule(db, src, tgt, cls, def, AVTAB_TRANSITION);
    }
}

bool ksu_type_change(struct policydb *db, const char *src, const char *tgt,
                     const char *cls, const char *def)
{
    return add_type_rule(db, src, tgt, cls, def, AVTAB_CHANGE);
}

bool ksu_type_member(struct policydb *db, const char *src, const char *tgt,
                     const char *cls, const char *def)
{
    return add_type_rule(db, src, tgt, cls, def, AVTAB_MEMBER);
}

// File system labeling
bool ksu_genfscon(struct policydb *db, const char *fs_name, const char *path,
                  const char *ctx)
{
    return add_genfscon(db, fs_name, path, ctx);
}

// ======== sepolicy ========

void ksu_destroy_sepolicy(struct selinux_policy *pol)
{
    policydb_destroy(&pol->policydb);
    kfree(pol);
}

struct selinux_policy *ksu_dup_sepolicy(struct selinux_policy *old_pol)
{
    int ret;
    size_t len;
    struct selinux_policy *new_pol;
    void *data;
    struct policy_file fp;

    // Some device policy db seems not marking type itself in type_attr_map_array
    // policydb_read() adds each type to its own attribute map, so old_pol->policydb.len may be smaller
    // preserve one ebitmap entry for this condition to avoid trigger -EINVAL
    len = old_pol->policydb.len + (size_t)old_pol->policydb.p_types.nprim * (sizeof(u32) + sizeof(u64));

    data = vmalloc(len);
    if (!data) {
        pr_err("alloc policy buffer len %zu\n", len);
        ret = -ENOMEM;
        goto out_free_data;
    }

    fp.data = data;
    fp.len = len;

    ret = policydb_write(&old_pol->policydb, &fp);
    if (ret) {
        pr_err("sepolicy: policydb_write: %d\n", ret);
        goto out_free_data;
    }
    len -= fp.len;
    // https://android.googlesource.com/kernel/common/+/35a7845718734ae638b85b420534cb859498dab6%5E%21
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 18, 0)
    // https://android-review.googlesource.com/c/kernel/common/+/3009995/11/security/selinux/ss/policydb.c
    // fixup config
    // 4*2+8+4
    static const size_t kConfigOff = 20;
    if (len >= kConfigOff + sizeof(u32)) {
        u32 *config_ptr = (u32 *)((unsigned long)data + kConfigOff);
        pr_info("old config: %u\n", *config_ptr);
#ifdef POLICYDB_CONFIG_ANDROID_NETLINK_ROUTE
        if (old_pol->policydb.android_netlink_route) {
            pr_info("adding POLICYDB_CONFIG_ANDROID_NETLINK_ROUTE\n");
            *config_ptr |= POLICYDB_CONFIG_ANDROID_NETLINK_ROUTE;
        }
        if (old_pol->policydb.android_netlink_getneigh) {
            pr_info("adding POLICYDB_CONFIG_ANDROID_NETLINK_GETNEIGH\n");
            *config_ptr |= POLICYDB_CONFIG_ANDROID_NETLINK_GETNEIGH;
        }
#endif
        pr_info("new config: %u\n", *config_ptr);
    }
#endif
    new_pol = kmemdup(old_pol, sizeof(*old_pol), GFP_KERNEL);
    if (!new_pol) {
        ret = -ENOMEM;
        pr_err("sepolicy: dup old pol\n");
        goto out_free_data;
    }
    memset(&new_pol->policydb, 0, sizeof(new_pol->policydb));

    // rewind fp
    fp.data = data;
    fp.len = len;

    ret = policydb_read(&new_pol->policydb, &fp);
    if (ret) {
        pr_err("sepolicy: policydb_read: %d\n", ret);
        goto out_free_policydb;
    }
    new_pol->policydb.len = len;
    kvfree(data);

    return new_pol;

out_free_policydb:
    kfree(new_pol);

out_free_data:
    kvfree(data);

    return ERR_PTR(ret);
}

#endif
