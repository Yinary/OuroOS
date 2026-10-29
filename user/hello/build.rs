//! 按目标架构生成用户程序链接脚本。
//!
//! 用户程序链接到固定虚拟地址 0x10000（OuroOS 初版用户布局，
//! 见 kernel/src/mm/address_space.rs）。

use std::{env, fs, io, path::PathBuf};

fn main() -> io::Result<()> {
    let arch = env::var("CARGO_CFG_TARGET_ARCH").expect("can't find target");
    let output_arch = if arch.contains("riscv64") {
        "riscv"
    } else if arch.contains("loongarch64") {
        "loongarch64"
    } else {
        panic!("unsupported architecture: {arch}");
    };

    let content = fs::read_to_string("linker.lds")?.replace("%ARCH%", output_arch);
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let path = PathBuf::from(out_dir).join(format!("linker_{arch}.lds"));
    fs::write(&path, content)?;
    println!("cargo:rustc-link-arg=-T{}", path.display());
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=linker.lds");
    Ok(())
}
