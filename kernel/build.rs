//! 生成当前目标架构的链接脚本。
//!
//! VMA / 物理加载地址（LMA）与 QEMU 的加载约定保持一致：
//! - riscv64:     VMA 0xffffffc080200000，LMA(物理) 0x80200000（OpenSBI 位于 0x80000000）
//! - loongarch64: VMA 0x9000000080000000，LMA(物理) 0x80000000（经 DMW1 直接映射窗口）
//!
//! 参考来源：PolyHAL https://github.com/Byte-OS/polyhal example 目录
//! 原协议：MIT
//! 修改说明：按 OuroOS 的地址布局调整了模板参数与注释。

use std::{env, fs, io::Result, path::PathBuf};

fn main() -> Result<()> {
    gen_linker_script()
}

/// 按目标架构填充 linker.lds 模板并写入 OUT_DIR，
/// 再把脚本的绝对路径作为链接参数传给链接器。
fn gen_linker_script() -> Result<()> {
    let arch = env::var("CARGO_CFG_TARGET_ARCH").expect("can't find target");
    let fname = format!("linker_{arch}.lds");
    let (output_arch, virt_base, phys_base) = if arch.contains("riscv64") {
        ("riscv", "0xffffffc080200000", "0x80200000")
    } else if arch.contains("loongarch64") {
        ("loongarch64", "0x9000000080000000", "0x80000000")
    } else {
        panic!("unsupported architecture: {arch}");
    };

    let ld_content = fs::read_to_string("linker.lds")?;
    let ld_content = ld_content.replace("%ARCH%", output_arch);
    let ld_content = ld_content.replace("%VIRT_BASE%", virt_base);
    let ld_content = ld_content.replace("%PHYS_BASE%", phys_base);

    // 写到 OUT_DIR，用绝对路径传给链接器，避免依赖 cargo 的启动目录
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let out_path = PathBuf::from(out_dir).join(&fname);
    fs::write(&out_path, ld_content)?;
    println!("cargo:rustc-link-arg=-T{}", out_path.display());
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=linker.lds");
    Ok(())
}
