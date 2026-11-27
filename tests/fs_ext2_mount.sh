#!/usr/bin/env bash
# 在两架构分别挂载独立 Ext2 辅助盘，关机后检查两张盘。
set -euo pipefail

cd "$(dirname "$0")/.."
out=${1:-target/fs-validation/ext2-mount}
mkdir -p "$out"
out=$(realpath "$out")
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT

cp -a user "$tmp/user"
cp tests/fs_ext2_mount.rs "$tmp/user/src/bin/smoke.rs"
for arch in rv la; do
    if [[ "$arch" == rv ]]; then
        target=riscv64gc-unknown-none-elf
        flags=
        qemu=${QEMU_RV:-qemu-system-riscv64}
        machine=(-machine virt -bios default)
        devices=(-device virtio-blk-device,drive=root,bus=virtio-mmio-bus.0
                 -device virtio-blk-device,drive=aux,bus=virtio-mmio-bus.1)
    else
        target=loongarch64-unknown-none
        flags="-Zunstable-options -C target-feature=-lsx,-lasx"
        qemu=${QEMU_LA:-qemu-system-loongarch64}
        machine=()
        devices=(-device virtio-blk-pci,drive=root -device virtio-blk-pci,drive=aux)
    fi

    RUSTFLAGS="$flags" CARGO_TARGET_DIR="$tmp/user-target" timeout 150 cargo build \
        --manifest-path "$tmp/user/Cargo.toml" --bin smoke -Z build-std=core \
        --release --target "$target" > "$out/$arch-build.log" 2>&1
    root="$tmp/$arch-root.img"
    aux="$tmp/$arch-aux.img"
    truncate -s 64M "$root"
    truncate -s 384M "$aux"
    timeout 35 mkfs.ext4 -q -F -b 4096 "$root"
    timeout 35 mkfs.ext2 -q -F -b 1024 -I 128 -O none,dir_index,filetype,sparse_super "$aux"
    cat > "$tmp/fixture" <<EOF
mkdir /mnt
write /dev/null /mnt/underneath
write $tmp/user-target/$target/release/smoke /init
set_inode_field /init mode 0100755
EOF
    timeout 20 debugfs -w -f "$tmp/fixture" "$root" > "$out/$arch-fixture.log" 2>&1

    timeout -k 5 90 "$qemu" "${machine[@]}" -kernel "kernel-$arch" -m 1G \
        -smp 1 -nographic -no-reboot "${devices[@]}" \
        -drive "file=$root,format=raw,if=none,id=root" \
        -drive "file=$aux,format=raw,if=none,id=aux" > "$out/$arch.log" 2>&1
    grep -F 'EXT2 MOUNT PASS' "$out/$arch.log"
    timeout 35 e2fsck -fn "$root" > "$out/$arch-root-fsck.log" 2>&1
    timeout 35 e2fsck -fn "$aux" > "$out/$arch-aux-fsck.log" 2>&1
done
