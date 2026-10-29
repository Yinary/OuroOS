//! 受限的 ELF64 加载器。
//!
//! 只支持：ELF64 / 小端 / 目标架构匹配 / ET_EXEC 固定地址静态可执行文件。
//! 拒绝：动态解释器（PT_INTERP）、ET_DYN 等动态格式、页级重叠、越出
//! 用户范围的段、侵入栈保护页的段。
//!
//! 解析时全部用边界检查后的字段读取（小端字节序逐字段拼装），不把未
//! 对齐的文件字节 unsafe 转换成结构体引用。
//!
//! Linux 语义说明：真实内核还处理对齐、ELF 注释段、AT_ 辅助向量等，
//! 本轮均不支持；程序头表之外的 ELF 内容（节表、符号表）不参与加载。

use polyhal::pagetable::{MappingFlags, PAGE_SIZE};

use crate::mm::{
    address_space::{phys_to_kernel_vaddr, UserAddressSpace, USER_BASE},
    fence_icache,
};

/// 加载失败原因
#[derive(Debug)]
pub enum ElfError {
    /// 文件比 ELF 头还短
    Truncated,
    /// 魔数 / class / 数据序 / 版本不符合 ELF64 小端
    BadIdent,
    /// 只支持 ET_EXEC（2）：静态固定地址可执行文件
    BadType,
    /// e_machine 与当前目标架构不匹配
    BadMachine,
    /// 程序头表越界或 e_phentsize 不是 ELF64 标准值 56
    BadProgramHeaders,
    /// 存在 PT_INTERP：需要动态解释器，不支持
    Dynamic,
    /// PT_LOAD 参数非法（范围、对齐、filesz/memsz）
    BadSegment,
    /// 不同段落到同一页（页级权限无法表达，拒绝而不是覆盖）
    SegmentOverlap,
    /// 入口地址未落在可执行的用户映射中
    EntryInvalid,
    /// 映射失败（越出用户范围 / 侵入栈保护页等）
    MapFailed,
}

/// ELF64 文件头中用到的字段（按 ident 偏移）
const EI_CLASS: usize = 4;
const EI_DATA: usize = 5;
const EI_VERSION: usize = 6;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;

const ET_EXEC: u16 = 2;
/// riscv64 的 e_machine；loongarch64 为 EM_LOONGARCH = 258。
/// polyhal 未提供按目标架构取值的常量，这里只能按架构选择。
#[cfg(target_arch = "riscv64")]
const EM_CURRENT: u16 = 243;
#[cfg(target_arch = "loongarch64")]
const EM_CURRENT: u16 = 258;

const PT_LOAD: u32 = 1;
const PT_INTERP: u32 = 3;
/// ELF64 程序头固定大小
const PHENTSIZE: u16 = 56;

/// 程序头 p_flags 到页权限的映射。统一叠加 U 位（用户可访问）。
/// 注意 loongarch64 经 polyhal 无法表达 R/X 撤销（映射即隐含可读可执行），
/// 只有 W/U 受控；riscv64 完整表达 RWX。
fn segment_flags(p_flags: u32) -> MappingFlags {
    let mut flags = MappingFlags::U;
    if p_flags & 0x4 != 0 {
        flags |= MappingFlags::R;
    }
    if p_flags & 0x2 != 0 {
        flags |= MappingFlags::W;
    }
    if p_flags & 0x1 != 0 {
        flags |= MappingFlags::X;
    }
    flags
}

fn read_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

fn read_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
}

fn read_u64(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(buf[off..off + 8].try_into().unwrap())
}

/// 解析并把 ELF 加载进 `space`，返回入口虚拟地址。
///
/// BSS（memsz > filesz 的部分）依赖 [`UserAddressSpace::map_alloc`]
/// 返回已清零的页，无需显式清零。加载完成后执行指令缓存同步。
pub fn load_elf(space: &mut UserAddressSpace, elf: &[u8]) -> Result<usize, ElfError> {
    if elf.len() < 64 {
        return Err(ElfError::Truncated);
    }
    if elf[0] != 0x7f || elf[1] != b'E' || elf[2] != b'L' || elf[3] != b'F' {
        return Err(ElfError::BadIdent);
    }
    if elf[EI_CLASS] != ELFCLASS64 || elf[EI_DATA] != ELFDATA2LSB || elf[EI_VERSION] != 1 {
        return Err(ElfError::BadIdent);
    }
    let e_type = read_u16(elf, 16);
    let e_machine = read_u16(elf, 18);
    if e_type != ET_EXEC {
        return Err(ElfError::BadType);
    }
    if e_machine != EM_CURRENT {
        return Err(ElfError::BadMachine);
    }
    let e_entry = read_u64(elf, 24) as usize;
    let e_phoff = read_u64(elf, 32) as usize;
    let e_phentsize = read_u16(elf, 54);
    let e_phnum = read_u16(elf, 56);
    if e_phentsize != PHENTSIZE {
        return Err(ElfError::BadProgramHeaders);
    }
    let phnum = e_phnum as usize;
    // 程序头表边界（含溢出检查）
    let phend = e_phoff
        .checked_add(
            phnum
                .checked_mul(PHENTSIZE as usize)
                .ok_or(ElfError::BadProgramHeaders)?,
        )
        .ok_or(ElfError::BadProgramHeaders)?;
    if phend > elf.len() {
        return Err(ElfError::BadProgramHeaders);
    }

    for i in 0..phnum {
        let ph = e_phoff + i * PHENTSIZE as usize;
        let p_type = read_u32(elf, ph);
        match p_type {
            PT_INTERP => return Err(ElfError::Dynamic),
            PT_LOAD => load_segment(space, elf, ph)?,
            // PT_NOTE / PT_GNU_* 等与加载无关，忽略
            _ => continue,
        }
    }

    // 入口必须落在可执行的用户映射中
    let Some((_, flags)) = space.translate(e_entry) else {
        return Err(ElfError::EntryInvalid);
    };
    if !flags.contains(MappingFlags::U) || !entry_executable(flags) {
        return Err(ElfError::EntryInvalid);
    }

    // 代码页经内核别名写入、用户在用户地址取指，需同步指令缓存
    fence_icache();
    Ok(e_entry)
}

/// 入口映射是否可执行。riscv64 查 X 位；loongarch64 的 X 无法通过
/// polyhal 的权限转换撤回（映射即隐含可执行），只能确认映射属于用户。
fn entry_executable(flags: MappingFlags) -> bool {
    #[cfg(target_arch = "riscv64")]
    {
        flags.contains(MappingFlags::X)
    }
    #[cfg(target_arch = "loongarch64")]
    {
        let _ = flags;
        true
    }
}

/// 加载单个 PT_LOAD 段（`ph` 为该程序头在文件内的偏移）。
fn load_segment(space: &mut UserAddressSpace, elf: &[u8], ph: usize) -> Result<(), ElfError> {
    let p_flags = read_u32(elf, ph + 4);
    let p_offset = read_u64(elf, ph + 8) as usize;
    let p_vaddr = read_u64(elf, ph + 16) as usize;
    let p_filesz = read_u64(elf, ph + 32) as usize;
    let p_memsz = read_u64(elf, ph + 40) as usize;

    if p_filesz > p_memsz {
        return Err(ElfError::BadSegment);
    }
    // 文件范围检查
    let file_end = p_offset.checked_add(p_filesz).ok_or(ElfError::BadSegment)?;
    if file_end > elf.len() {
        return Err(ElfError::BadSegment);
    }
    // 用户范围与栈保护检查（含溢出）
    UserAddressSpace::check_user_span(p_vaddr, p_memsz).map_err(|_| ElfError::BadSegment)?;
    if p_vaddr < USER_BASE {
        return Err(ElfError::BadSegment);
    }
    // 我们按 4KiB 页映射：虚拟地址必须页对齐；文件偏移只在段含文件
    // 内容时要求页对齐（纯 BSS 段 filesz=0，无偏移约束）
    if p_vaddr % PAGE_SIZE != 0 || (p_filesz > 0 && p_offset % PAGE_SIZE != 0) {
        return Err(ElfError::BadSegment);
    }
    if p_memsz == 0 {
        return Ok(());
    }

    let flags = segment_flags(p_flags);
    let pages = p_memsz.div_ceil(PAGE_SIZE);
    for i in 0..pages {
        let vaddr = p_vaddr + i * PAGE_SIZE;
        // 页级重叠拒绝：map_alloc 检查目标页是否已有映射
        let paddr = space
            .map_alloc(vaddr, flags)
            .map_err(|_| ElfError::SegmentOverlap)?;
        // 复制文件内容（BSS 部分依赖新页已清零）
        let file_off = p_offset + i * PAGE_SIZE;
        let copy_len = p_filesz.saturating_sub(i * PAGE_SIZE).min(PAGE_SIZE);
        if copy_len > 0 {
            let dst = phys_to_kernel_vaddr(paddr);
            // SAFETY: paddr 是刚为本段分配并清零的物理页；copy_len 由
            // p_filesz（已做文件边界检查）限定，源与目标都不越界。
            unsafe {
                core::ptr::copy_nonoverlapping(
                    elf.as_ptr().add(file_off),
                    dst as *mut u8,
                    copy_len,
                );
            }
        }
    }
    Ok(())
}
