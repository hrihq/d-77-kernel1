# D-77 Kernel1

**D-77 Kernel1** untuk **Xiaomi Redmi Note 12 Pro 4G (sweet_k6a)**.

Linux 4.14 kernel, LineageOS-based, KernelSU Next terintegrasi.

## Device info

- Device: Redmi Note 12 Pro 4G
- Codename: `sweet_k6a`
- SoC: Qualcomm SM7325 (Snapdragon 732G)
- Kernel: Linux 4.14.336
- Root: KernelSU Next 3.4.0 (syscall table hook)
- Target: Android 16 boot

## Branches

- `lineage-22` — upstream mirror LineageOS 22 (Pulkit077/kernel_xiaomi_sweet_k6a), unmodified
- `lineage-21` — upstream mirror LineageOS 21, unmodified
- `d-77` — D-77 branding + KernelSU Next + Android 16 BPF support

## Build

```bash
make O=out ARCH=arm64 sweet_k6a_user_defconfig
make O=out ARCH=arm64 -j$(nproc) \
  CC=clang \
  CLANG_TRIPLE=aarch64-linux-gnu- \
  CROSS_COMPILE=aarch64-linux-gnu- \
  CROSS_COMPILE_ARM32=arm-linux-gnu-
```

Output: `out/arch/arm64/boot/Image.gz-dtb`

## Credits

- **Pulkit077** — original kernel_xiaomi_sweet_k6a tree, device bringup
- LineageOS — base kernel
- **KernelSU-Next** — root solution (v3.4.0)
- **hrihq (D-77)** — rebrand, KSU integration, BPF updates

## License

GNU GPL-2.0-only, same as Linux kernel.
