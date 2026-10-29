//! 生成当前目标架构的链接脚本，并把用户程序 ELF 内嵌进内核。
//!
//! VMA / 物理加载地址（LMA）与 QEMU 的加载约定保持一致：
//! - riscv64:     VMA 0xffffffc080200000，LMA(物理) 0x80200000（OpenSBI 位于 0x80000000）
//! - loongarch64: VMA 0x9000000080000000，LMA(物理) 0x80000000（经 DMW1 直接映射窗口）
//!
//! 用户镜像由 Makefile 先构建（`make build-user-rv` / `build-user-la`），
//! 再通过环境变量 OUROOS_HELLO_ELF / OUROOS_CHECK_ELF 传入路径，复制到
//! OUT_DIR 后以 include_bytes! 引用；rustc 的 dep-info 会跟踪被包含
//! 文件的变化，ELF 更新后内核会自动重编。
//!
//! 参考来源：PolyHAL https://github.com/Byte-OS/polyhal example 目录
//! 原协议：MIT
//! 修改说明：按 OuroOS 的地址布局调整了模板参数与注释；新增用户 ELF 内嵌。

use std::{env, fs, io, path::PathBuf};

fn main() -> io::Result<()> {
    gen_linker_script()?;
    embed_user_images()?;
    Ok(())
}

/// 按目标架构填充 linker.lds 模板并写入 OUT_DIR，
/// 再把脚本的绝对路径作为链接参数传给链接器。
fn gen_linker_script() -> io::Result<()> {
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

/// 内嵌镜像描述：(环境变量, 文件名, 生成的静态符号名)
const IMAGES: [(&str, &str, &str); 2] = [
    ("OUROOS_HELLO_ELF", "hello", "HELLO_ELF"),
    ("OUROOS_CHECK_ELF", "check", "CHECK_ELF"),
];

/// 复制用户 ELF 到 OUT_DIR 并生成 user_images.rs。
///
/// 环境变量缺失时（例如脱离 Makefile 直接 `cargo check`）生成空镜像并
/// 打印警告，内核仍可编译；运行时会以加载失败报告，不会误当成功。
fn embed_user_images() -> io::Result<()> {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    // 构建脚本的工作目录是包根（kernel/），而 Makefile 传入的用户 ELF
    // 路径相对于仓库根，需要先 absolutize
    let workspace_root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("kernel/ 的上级目录")
        .to_path_buf();

    let mut code = String::from(
        "// 由 build.rs 生成：内嵌的用户程序 ELF（构建见 Makefile 与 user/hello）。\n",
    );
    for (var, name, symbol) in IMAGES {
        match env::var(var) {
            Ok(path) => {
                let src = PathBuf::from(&path);
                let src = if src.is_relative() {
                    workspace_root.join(src)
                } else {
                    src
                };
                let dst = out_dir.join(format!("{name}.elf"));
                fs::copy(&src, &dst)?;
                // 源文件或环境变量变化时重跑本脚本；rustc 侧由 dep-info
                // 跟踪 OUT_DIR 中的副本
                println!("cargo:rerun-if-env-changed={var}");
                println!("cargo:rerun-if-changed={}", src.display());
                code.push_str(&format!(
                    "/// {name} 用户程序（构建产物，请勿手改）\n\
                     pub static {symbol}: &[u8] = include_bytes!(\"{name}.elf\");\n"
                ));
            }
            Err(_) => {
                println!(
                    "cargo:warning={var} 未设置：嵌入空镜像（请通过 make all 构建以嵌入用户程序）"
                );
                code.push_str(&format!(
                    "/// {name} 用户程序：构建时未提供（空镜像，运行时会报告加载失败）\n\
                     pub static {symbol}: &[u8] = &[];\n"
                ));
            }
        }
    }
    fs::write(out_dir.join("user_images.rs"), code)?;
    println!("cargo:rerun-if-changed=build.rs");
    Ok(())
}
