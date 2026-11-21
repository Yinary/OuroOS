//! 受限的 ELF64 加载器：静态 ET_EXEC 与带装载基址的 ET_DYN
//! （ELF64/小端/架构匹配），逐字段边界检查解析，不把文件字节重解释为
//! 结构体引用。PT_INTERP 请求由调用方（exec）装载解释器并构造初栈。
//! 支持范围与 Linux 差异见 docs/ostd-contracts.md §4。

#![deny(unsafe_code)]

use alloc::string::String;
use polyhal::pagetable::{MappingFlags, PAGE_SIZE};

use crate::mm::{address_space::UserAddressSpace, fence_icache};

/// 加载失败原因
#[derive(Debug)]
pub enum ElfError {
    /// 用户数据页、页表页或管理元数据不足。
    OutOfMemory,
    /// 文件比 ELF 头还短
    Truncated,
    /// 魔数 / class / 数据序 / 版本不符合 ELF64 小端
    BadIdent,
    /// e_type 不是 ET_EXEC（2）或 ET_DYN（3）
    BadType,
    /// e_machine 与当前目标架构不匹配
    BadMachine,
    /// 程序头表越界或 e_phentsize 不是 ELF64 标准值 56
    BadProgramHeaders,
    /// PT_INTERP 参数非法（越界、无 NUL 结尾、非 UTF-8 或出现多个）
    BadInterp,
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
const ET_DYN: u16 = 3;
/// riscv64 的 e_machine；loongarch64 为 EM_LOONGARCH = 258。
/// polyhal 未提供按目标架构取值的常量，这里只能按架构选择。
#[cfg(target_arch = "riscv64")]
const EM_CURRENT: u16 = 243;
#[cfg(target_arch = "loongarch64")]
const EM_CURRENT: u16 = 258;

/// ET_DYN 主映像的装载基址。取 1 MiB 而非 Linux 的 TASK_SIZE/3*2 高位布局：
/// 高位基址是 Linux 的 ASLR 策略而非 ABI 要求，且官方测例把 brk 返回值按
/// 32 位 int 处理，高位堆地址在 Linux 上同样使其失效；1 MiB 同时避开 0 页，
/// 空指针解引用仍然缺页。
pub fn et_dyn_base() -> usize {
    0x10_0000
}

const PT_LOAD: u32 = 1;
const PT_INTERP: u32 = 3;
/// ELF64 程序头固定大小
const PHENTSIZE: u16 = 56;

/// 程序头 p_flags 到页权限的映射。统一叠加 U 位（用户可访问）。
/// 记录 ELF 请求权限；两架构均不提供 NX，实际可访问页允许执行。
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
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

fn read_u64(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
        buf[off + 4],
        buf[off + 5],
        buf[off + 6],
        buf[off + 7],
    ])
}

/// 已校验的程序入口及位于可读 LOAD 段内的程序头表。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageInfo {
    /// 用户入口（已加装载基址）
    pub entry: usize,
    /// 程序头表位置（AT_PHDR/AT_PHENT/AT_PHNUM，已加装载基址）；
    /// 仅当程序头表整体落在某个可读 LOAD 段内时给出。
    pub headers: Option<(usize, usize, usize)>,
    /// 本映像的装载基址（ET_EXEC 为 0，供 AT_BASE 使用）
    pub base: usize,
    /// PT_INTERP 请求的解释器绝对路径（仅主映像解析；解释器不允许嵌套请求）
    pub interp: Option<String>,
}

/// 只解析 ELF 头，取出 PT_INTERP 请求的解释器路径（不触达地址空间）。
/// 供 exec 在持有注册表借用时预读解释器文件。
pub fn interp_path(elf: &[u8]) -> Result<Option<String>, ElfError> {
    parse_header(elf).map(|(_, interp)| interp)
}

/// 解析并把主映像 ELF 加载进 `space`，返回入口与 auxv 所需信息。
///
/// ET_EXEC 使用固定地址（基址 0）；ET_DYN 以 [`et_dyn_base`] 为装载基址。
/// BSS（memsz > filesz 的部分）依赖 [`UserAddressSpace::map_alloc`]
/// 返回已清零的页，无需显式清零。加载完成后执行指令缓存同步。
pub fn load_elf(space: &mut UserAddressSpace, elf: &[u8]) -> Result<ImageInfo, ElfError> {
    let (e_type, interp) = parse_header(elf)?;
    let bias = match e_type {
        ET_EXEC => 0,
        ET_DYN => et_dyn_base(),
        _ => return Err(ElfError::BadType),
    };
    let mut staged = UserAddressSpace::new().map_err(map_error)?;
    let info = load_image(&mut staged, elf, bias, interp)?;
    space.install_image(staged).map_err(map_error)?;
    fence_icache();
    Ok(info)
}

/// 在已构造的地址空间内装载解释器映像（响应主映像的 PT_INTERP）。
///
/// 解释器自身的 ET_EXEC 使用固定地址；ET_DYN 在栈保护区下方寻找空洞
/// 作为装载基址，避免与主映像或栈冲突。返回值供 AT_BASE 与初次 PC 使用。
pub fn load_interp(space: &mut UserAddressSpace, elf: &[u8]) -> Result<ImageInfo, ElfError> {
    let (e_type, interp) = parse_header(elf)?;
    if interp.is_some() {
        // 解释器再请求解释器不符合 ELF/ABI，直接拒绝
        return Err(ElfError::BadInterp);
    }
    let bias = match e_type {
        ET_EXEC => 0,
        ET_DYN => {
            // 放置约束（审查 R5d）：bias 须对齐全部段有效的最大 p_align，
            // 且实际区间 [bias+min_vaddr, bias+min_vaddr+span] 整体落在
            // 空洞内。找洞时多留 align 页余量，取"洞尾 - 映像跨度"向下
            // 对齐为 bias；起点 = bias+min ≥ 洞头由余量严格保证（推导：
            // align_down(H+A-min,A)+min ≥ H+1），非零最低 vaddr 或大
            // 对齐映像都不会把段起点移出已检查范围。
            let (min_vaddr, pages, align) = image_span(elf)?;
            let align = align.max(PAGE_SIZE);
            let top = crate::mm::address_space::USER_TOP;
            let slack = align / PAGE_SIZE;
            let hole = space
                .find_free(top - 0x1000_0000, pages + slack)
                .map_err(map_error)?;
            let span_bytes = pages * PAGE_SIZE;
            let hole_end = hole + (pages + slack) * PAGE_SIZE;
            hole_end
                .checked_sub(min_vaddr)
                .and_then(|end| end.checked_sub(span_bytes))
                .map(|x| x & !(align - 1))
                .ok_or(ElfError::MapFailed)?
        }
        _ => return Err(ElfError::BadType),
    };
    let info = load_image(space, elf, bias, None)?;
    fence_icache();
    Ok(info)
}

/// 头部公共校验：魔数、class、e_type、e_machine、程序头表边界。
/// 返回 (e_type, PT_INTERP 路径)。
fn parse_header(elf: &[u8]) -> Result<(u16, Option<String>), ElfError> {
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
    if read_u32(elf, 20) != 1 || read_u16(elf, 52) != 64 {
        return Err(ElfError::BadIdent);
    }
    if e_type != ET_EXEC && e_type != ET_DYN {
        return Err(ElfError::BadType);
    }
    if e_machine != EM_CURRENT {
        return Err(ElfError::BadMachine);
    }
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

    let mut interp = None;
    for i in 0..phnum {
        let ph = e_phoff + i * PHENTSIZE as usize;
        if read_u32(elf, ph) == PT_INTERP {
            if interp.is_some() {
                return Err(ElfError::BadInterp);
            }
            let offset = read_u64(elf, ph + 8) as usize;
            let filesz = read_u64(elf, ph + 32) as usize;
            let end = offset.checked_add(filesz).ok_or(ElfError::BadInterp)?;
            if filesz < 2 || end > elf.len() || elf[end - 1] != 0 {
                return Err(ElfError::BadInterp);
            }
            let text =
                core::str::from_utf8(&elf[offset..end - 1]).map_err(|_| ElfError::BadInterp)?;
            if text.is_empty() || text.contains('\0') {
                return Err(ElfError::BadInterp);
            }
            let mut path = String::new();
            path.try_reserve(text.len())
                .map_err(|_| ElfError::BadInterp)?;
            path.push_str(text);
            interp = Some(path);
        }
    }
    Ok((e_type, interp))
}

/// ET_DYN 映像所有 PT_LOAD 段合计占据的页数（用于寻找装载空洞）。
/// ET_DYN 映像的跨度信息：最低 PT_LOAD 起址、占据页数、全部段中
/// 有效的最大 p_align（装载基址需满足该对齐）。
fn image_span(elf: &[u8]) -> Result<(usize, usize, usize), ElfError> {
    let e_phoff = read_u64(elf, 32) as usize;
    let phnum = read_u16(elf, 56) as usize;
    let mut min: Option<usize> = None;
    let mut max = 0usize;
    let mut align = PAGE_SIZE;
    for i in 0..phnum {
        let ph = e_phoff + i * PHENTSIZE as usize;
        if read_u32(elf, ph) != PT_LOAD {
            continue;
        }
        let vaddr = read_u64(elf, ph + 16) as usize;
        let memsz = read_u64(elf, ph + 40) as usize;
        let p_align = read_u64(elf, ph + 48) as usize;
        let end = vaddr.checked_add(memsz).ok_or(ElfError::BadSegment)?;
        min = Some(min.map_or(vaddr, |m| m.min(vaddr)));
        max = max.max(end);
        if p_align.is_power_of_two() && p_align > 1 {
            align = align.max(p_align);
        }
    }
    let min = min.ok_or(ElfError::BadSegment)?;
    let pages = max.div_ceil(PAGE_SIZE) - min / PAGE_SIZE;
    Ok((min, pages.max(1), align))
}

fn map_error(e: crate::mm::address_space::MapError) -> ElfError {
    use crate::mm::address_space::MapError;
    match e {
        MapError::OutOfMemory => ElfError::OutOfMemory,
        MapError::Overlap => ElfError::SegmentOverlap,
        _ => ElfError::MapFailed,
    }
}

/// 把映像按装载基址 `bias` 装入 `space`（不新建地址空间）。
fn load_image(
    space: &mut UserAddressSpace,
    elf: &[u8],
    bias: usize,
    interp: Option<String>,
) -> Result<ImageInfo, ElfError> {
    let e_entry = read_u64(elf, 24) as usize;
    let e_phoff = read_u64(elf, 32) as usize;
    let phnum = read_u16(elf, 56) as usize;
    let phend = e_phoff + phnum * PHENTSIZE as usize;

    for i in 0..phnum {
        let ph = e_phoff + i * PHENTSIZE as usize;
        let p_type = read_u32(elf, ph);
        if p_type == PT_LOAD {
            load_segment(space, elf, ph, bias)?;
        }
        // PT_INTERP 已在 parse_header 收集；PT_NOTE / PT_GNU_* 等与加载无关
    }

    let entry = e_entry.checked_add(bias).ok_or(ElfError::EntryInvalid)?;
    let entry_in_segment = (0..phnum).any(|i| {
        let ph = e_phoff + i * PHENTSIZE as usize;
        let start = read_u64(elf, ph + 16) as usize;
        let size = read_u64(elf, ph + 40) as usize;
        read_u32(elf, ph) == PT_LOAD
            && read_u32(elf, ph + 4) & 1 != 0
            && start <= e_entry
            && start.checked_add(size).is_some_and(|end| e_entry < end)
    });
    if !entry_in_segment {
        return Err(ElfError::EntryInvalid);
    }
    // 入口必须落在可执行的用户映射中
    let Some((_, flags)) = space.translate(entry) else {
        return Err(ElfError::EntryInvalid);
    };
    if !flags.contains(MappingFlags::U)
        || !space
            .areas()
            .iter()
            .any(|a| a.start <= entry && entry < a.end && a.flags.contains(MappingFlags::X))
    {
        return Err(ElfError::EntryInvalid);
    }

    let headers = (0..phnum).find_map(|i| {
        let ph = e_phoff + i * PHENTSIZE as usize;
        let offset = read_u64(elf, ph + 8) as usize;
        let va = read_u64(elf, ph + 16) as usize;
        let size = read_u64(elf, ph + 32) as usize;
        if read_u32(elf, ph) != PT_LOAD
            || read_u32(elf, ph + 4) & 4 == 0
            || offset > e_phoff
            || phend > offset.checked_add(size)?
        {
            return None;
        }
        Some((
            va.checked_add(bias)?.checked_add(e_phoff - offset)?,
            PHENTSIZE as usize,
            phnum,
        ))
    });
    Ok(ImageInfo {
        entry,
        headers,
        base: bias,
        interp,
    })
}

/// 加载单个 PT_LOAD 段（`ph` 为该程序头在文件内的偏移）。
/// `bias` 为装载基址，加到每个虚拟地址上；相位检查针对文件原始值。
fn load_segment(
    space: &mut UserAddressSpace,
    elf: &[u8],
    ph: usize,
    bias: usize,
) -> Result<(), ElfError> {
    let p_flags = read_u32(elf, ph + 4);
    let p_offset = read_u64(elf, ph + 8) as usize;
    let p_vaddr = read_u64(elf, ph + 16) as usize;
    let p_filesz = read_u64(elf, ph + 32) as usize;
    let p_memsz = read_u64(elf, ph + 40) as usize;
    let p_align = read_u64(elf, ph + 48) as usize;

    if p_filesz > p_memsz {
        return Err(ElfError::BadSegment);
    }
    // 文件范围检查
    let file_end = p_offset.checked_add(p_filesz).ok_or(ElfError::BadSegment)?;
    if file_end > elf.len() {
        return Err(ElfError::BadSegment);
    }
    let vaddr = p_vaddr.checked_add(bias).ok_or(ElfError::BadSegment)?;
    // 用户范围与栈保护检查（含溢出）
    UserAddressSpace::check_user_span(vaddr, p_memsz).map_err(|_| ElfError::BadSegment)?;
    if p_vaddr % PAGE_SIZE != p_offset % PAGE_SIZE
        || (p_align > 1 && (!p_align.is_power_of_two() || p_vaddr % p_align != p_offset % p_align))
    {
        return Err(ElfError::BadSegment);
    }
    if p_memsz == 0 {
        return Ok(());
    }

    let flags = segment_flags(p_flags);
    let page_start = vaddr / PAGE_SIZE * PAGE_SIZE;
    let mem_end = vaddr.checked_add(p_memsz).ok_or(ElfError::BadSegment)?;
    let file_va_end = vaddr.checked_add(p_filesz).ok_or(ElfError::BadSegment)?;
    for page in (page_start..mem_end).step_by(PAGE_SIZE) {
        space.map_alloc(page, flags).map_err(map_error)?;
        let begin = page.max(vaddr);
        let end = (page + PAGE_SIZE).min(file_va_end);
        if begin < end {
            let file_off = p_offset + (begin - vaddr);
            space
                .init_elf_page(begin, &elf[file_off..file_off + end - begin])
                .map_err(map_error)?;
        }
    }
    Ok(())
}

/// 合成 ELF 验证页内偏移、BSS、输入拒绝与逐点帧耗尽回滚。
#[cfg(debug_assertions)]
pub(crate) fn self_test() {
    use crate::mm::{
        frame,
        user_access::{copy_from_user, copy_to_user},
    };
    use polyhal::pagetable::MappingFlags as F;
    let baseline = frame::stats();
    let mut bytes = alloc::vec![0u8; 0x1223];
    bytes[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
    bytes[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
    bytes[18..20].copy_from_slice(&EM_CURRENT.to_le_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&0x10123u64.to_le_bytes());
    bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
    bytes[64..68].copy_from_slice(&PT_LOAD.to_le_bytes());
    bytes[68..72].copy_from_slice(&7u32.to_le_bytes());
    for (off, value) in [
        (72, 0x123u64),
        (80, 0x10123),
        (96, 0x1100),
        (104, 0x2100),
        (112, 4096),
    ] {
        bytes[off..off + 8].copy_from_slice(&value.to_le_bytes());
    }
    bytes[0x123..].fill(0x5a);
    let mut success = false;
    for budget in 0..24 {
        let mut space = UserAddressSpace::new().expect("ELF test space");
        space.map_alloc(0x40000, F::URW).expect("ELF sentinel");
        copy_to_user(&space, 0x40000, &[0x33]).expect("sentinel write");
        let before = frame::stats();
        frame::set_test_budget(Some(budget));
        let result = load_elf(&mut space, &bytes);
        frame::set_test_budget(None);
        let mut value = [0];
        copy_from_user(&space, 0x40000, &mut value).expect("sentinel read");
        assert_eq!(value, [0x33]);
        if result.is_ok() {
            for (va, expected) in [
                (0x10000, 0),
                (0x10123, 0x5a),
                (0x11000, 0x5a),
                (0x11222, 0x5a),
                (0x11223, 0),
                (0x12222, 0),
            ] {
                copy_from_user(&space, va, &mut value).expect("ELF bytes");
                assert_eq!(value, [expected]);
            }
            success = true;
            break;
        }
        assert!(matches!(result, Err(ElfError::OutOfMemory)));
        assert_eq!(frame::stats(), before);
        assert!(space.translate(0x10000).is_none());
    }
    assert!(success);
    for (offset, replacement) in [(72, u64::MAX), (104, u64::MAX), (112, 3), (24, 0x10000)] {
        let mut bad = bytes.clone();
        bad[offset..offset + 8].copy_from_slice(&replacement.to_le_bytes());
        let mut space = UserAddressSpace::new().expect("bad ELF test");
        let before = frame::stats();
        assert!(load_elf(&mut space, &bad).is_err());
        assert!(space.areas().is_empty());
        assert_eq!(frame::stats(), before);
    }
    assert_eq!(frame::stats(), baseline);
    log::info!("elf: offset, BSS, bounds and OOM rollback passed");
}
