//! execve 的参数复制、初始栈构造和地址空间事务切换。
#![deny(unsafe_code)]
use super::{Pid, REGISTRY};
use crate::{
    elf,
    fs::context,
    mm::{
        address_space::{LocalSpace, UserAddressSpace, USER_STACK_TOP},
        user_access,
    },
    syscall::Errno,
};
use alloc::{string::String, vec::Vec};
use polyhal_trap::trapframe::{TrapFrame, TrapFrameArgs};

fn strings(space: &UserAddressSpace, ptr: usize) -> Result<Vec<String>, Errno> {
    let mut out = Vec::new();
    if ptr == 0 {
        return Ok(out);
    }
    for i in 0..256usize {
        let mut word = [0u8; 8];
        user_access::copy_from_user(
            space,
            ptr.checked_add(i * 8).ok_or(Errno::Fault)?,
            &mut word,
        )
        .map_err(|_| Errno::Fault)?;
        let address = usize::from_ne_bytes(word);
        if address == 0 {
            return Ok(out);
        }
        out.try_reserve(1).map_err(|_| Errno::NoMem)?;
        out.push(crate::syscall::fs::user_string(space, address)?);
    }
    Err(Errno::TooBig)
}
/// 布置 argc/argv/envp/auxv，栈顶按 16 字节对齐。
///
/// `interp` 为解释器的 (入口, 基址)，存在时初次 PC 与 AT_BASE 取解释器；
/// `execfn` 是被执行的路径名（AT_EXECFN，区别于 argv[0]）；
/// `ids` 是真实与有效的用户号、组号，填入 AT_UID 等四项。
pub fn stack(
    space: &UserAddressSpace,
    argv: &[String],
    envp: &[String],
    image: &elf::ImageInfo,
    interp: Option<(usize, usize)>,
    execfn: &str,
    ids: [u32; 4],
) -> Result<usize, Errno> {
    let mut sp = USER_STACK_TOP;
    let mut pointers = Vec::new();
    pointers
        .try_reserve(argv.len() + envp.len())
        .map_err(|_| Errno::NoMem)?;
    let mut total = 0usize;
    for value in argv.iter().chain(envp.iter()) {
        total = total.checked_add(value.len() + 1).ok_or(Errno::TooBig)?;
        if total > 32768 {
            return Err(Errno::TooBig);
        }
        sp = sp.checked_sub(value.len() + 1).ok_or(Errno::TooBig)?;
        user_access::copy_to_user(space, sp, value.as_bytes()).map_err(|_| Errno::TooBig)?;
        user_access::copy_to_user(space, sp + value.len(), &[0]).map_err(|_| Errno::TooBig)?;
        pointers.push(sp);
    }
    // AT_EXECFN 的路径名串（execve 的路径，非 argv[0]）
    total = total.checked_add(execfn.len() + 1).ok_or(Errno::TooBig)?;
    if total > 32768 {
        return Err(Errno::TooBig);
    }
    sp = sp.checked_sub(execfn.len() + 1).ok_or(Errno::TooBig)?;
    user_access::copy_to_user(space, sp, execfn.as_bytes()).map_err(|_| Errno::TooBig)?;
    user_access::copy_to_user(space, sp + execfn.len(), &[0]).map_err(|_| Errno::TooBig)?;
    let execfn_ptr = sp;

    let random = require_random(crate::entropy::exec_random())?;
    sp = sp.checked_sub(random.len()).ok_or(Errno::TooBig)?;
    user_access::copy_to_user(space, sp, &random).map_err(|_| Errno::TooBig)?;
    let random_ptr = sp;

    // auxv：键值对序列，随映像信息变化；AT_NULL 结尾。
    let mut auxv: Vec<usize> = Vec::new();
    auxv.try_reserve(28).map_err(|_| Errno::NoMem)?;
    if let Some((phdr, size, count)) = image.headers {
        auxv.extend_from_slice(&[3, phdr, 4, size, 5, count]);
    }
    auxv.extend_from_slice(&[
        6,
        4096, // AT_PAGESZ
        7,
        interp.map_or(0, |p| p.1), // AT_BASE
        8,
        0, // AT_FLAGS
        9,
        image.entry, // AT_ENTRY
        11,
        ids[0] as usize, // AT_UID
        12,
        ids[1] as usize, // AT_EUID
        13,
        ids[2] as usize, // AT_GID
        14,
        ids[3] as usize, // AT_EGID
        16,
        0, // AT_HWCAP
        17,
        100, // AT_CLKTCK
        23,
        0, // AT_SECURE
        25,
        random_ptr, // AT_RANDOM
        31,
        execfn_ptr, // AT_EXECFN
        0,
        0, // AT_NULL
    ]);

    let mut words = Vec::new();
    words
        .try_reserve(pointers.len() + auxv.len() + 2)
        .map_err(|_| Errno::NoMem)?;
    words.push(argv.len());
    words.extend_from_slice(&pointers[..argv.len()]);
    words.push(0);
    words.extend_from_slice(&pointers[argv.len()..]);
    words.push(0);
    words.extend_from_slice(&auxv);
    sp = sp.checked_sub(words.len() * 8).ok_or(Errno::TooBig)? & !15;
    for (i, word) in words.iter().enumerate() {
        user_access::copy_to_user(space, sp + i * 8, &word.to_ne_bytes())
            .map_err(|_| Errno::TooBig)?;
    }
    Ok(sp)
}
/// 解析 `#!` 脚本头（binfmt_script 语义）：返回（解释器路径, 可选单参数）。
/// 解释器路径与其后的一个参数由空白分隔；参数保留内部空格。
fn parse_shebang(image: &[u8]) -> Option<(alloc::string::String, Option<alloc::string::String>)> {
    if !image.starts_with(b"#!") {
        return None;
    }
    let body = &image[2..];
    let line_end = body.iter().position(|&b| b == b'\n').unwrap_or(body.len());
    let line = core::str::from_utf8(&body[..line_end]).ok()?;
    let line = line.trim_matches(|c: char| c == '\r' || c.is_ascii_whitespace());
    let trimmed = line.trim_start();
    let mut split = trimmed.splitn(2, ' ');
    let interp = split.next().unwrap_or("");
    if interp.is_empty() || interp.contains(char::is_whitespace) {
        return None;
    }
    let mut interp_path = alloc::string::String::new();
    interp_path.try_reserve(interp.len()).ok()?;
    interp_path.push_str(interp);
    let arg = split
        .next()
        .map(|a| a.trim_end())
        .filter(|a| !a.is_empty())
        .and_then(|a| {
            let mut s = alloc::string::String::new();
            s.try_reserve(a.len()).ok()?;
            s.push_str(a);
            Some(s)
        });
    Some((interp_path, arg))
}

/// 全部准备成功才替换旧地址空间，失败保留原程序和现场。
pub fn exec(pid: Pid, args: [usize; 3], frame: &mut TrapFrame) -> Result<(), Errno> {
    let (image, interp_image, argv, envp, path) = {
        let reg = REGISTRY.lock();
        let rec = reg.group(pid).ok_or(Errno::Invalid)?;
        let space = rec.space.as_ref().ok_or(Errno::Invalid)?.as_space();
        let path = crate::syscall::fs::user_string(space, args[0])?;
        let mut argv = strings(space, args[1])?;
        let envp = strings(space, args[2])?;
        let fs = rec.fs.as_ref().ok_or(Errno::Invalid)?;
        let mut image = context::executable(fs, &path)?;
        let mut depth = 0;
        // #! 脚本转交解释器（binfmt_script；嵌套上限对齐 Linux 的 4 层）。
        // argv[0] 被替换为解释器，脚本路径作为解释器的首个操作数。
        let mut script_path = path.clone();
        loop {
            let Some((interp_path, script_arg)) = parse_shebang(&image) else {
                break;
            };
            depth += 1;
            if depth > 4 {
                return Err(Errno::Loop);
            }
            let mut next_argv: Vec<alloc::string::String> = Vec::new();
            next_argv
                .try_reserve(argv.len() + 2)
                .map_err(|_| Errno::NoMem)?;
            let mut interp_arg0 = alloc::string::String::new();
            interp_arg0
                .try_reserve(interp_path.len())
                .map_err(|_| Errno::NoMem)?;
            interp_arg0.push_str(&interp_path);
            next_argv.push(interp_arg0);
            if let Some(arg) = script_arg {
                next_argv.push(arg);
            }
            next_argv.push(alloc::string::String::from(&script_path[..]));
            next_argv.extend(argv.into_iter().skip(1));
            argv = next_argv;
            script_path = interp_path;
            image = context::executable(fs, &script_path)?;
        }
        // PT_INTERP 请求的解释器：缺失按 Linux 返回 ENOENT，旧进程保留
        let interp_image = elf::interp_path(&image)
            .map_err(|_| Errno::ExecFormat)?
            .map(|p| context::executable(fs, &p))
            .transpose()?;
        (image, interp_image, argv, envp, path)
    };
    let mut space = UserAddressSpace::new().map_err(|_| Errno::NoMem)?;
    let ids = {
        let reg = REGISTRY.lock();
        let current = reg.group(pid).ok_or(Errno::Invalid)?;
        space.inherit_memory_limits(current.space.as_ref().ok_or(Errno::Invalid)?.as_space());
        let c = &current.creds;
        [c.ruid, c.euid, c.rgid, c.egid]
    };
    let load_error = |e: elf::ElfError| {
        if matches!(e, elf::ElfError::OutOfMemory) {
            Errno::NoMem
        } else {
            Errno::ExecFormat
        }
    };
    let main = elf::load_elf(&mut space, &image).map_err(load_error)?;
    // 堆起点只跟主映像（Linux mm->brk 语义），必须先于解释器装载计算
    space.init_heap();
    // 解释器与主映像共置同一临时地址空间，两个映像及栈全部就绪才发布
    let interp = match (&interp_image, &main.interp) {
        (Some(bytes), Some(_)) => Some(elf::load_interp(&mut space, bytes).map_err(load_error)?),
        (None, None) => None,
        // 头部声明 PT_INTERP 但文件未读到（前一步已报 ENOENT），不可达
        _ => return Err(Errno::ExecFormat),
    };
    let entry = interp.as_ref().map_or(main.entry, |i| i.entry);
    space.map_stack().map_err(|_| Errno::NoMem)?;
    let sp = stack(
        &space,
        &argv,
        &envp,
        &main,
        interp.as_ref().map(|i| (i.entry, i.base)),
        &path,
        ids,
    )?;
    let mut next = TrapFrame::new();
    next[TrapFrameArgs::SEPC] = entry;
    next[TrapFrameArgs::SP] = sp;
    // —— 可失败准备段：procfs 的 cmdline 与可执行路径在此备齐，任何
    // 分配/路径失败都直接返回，旧地址空间、trap frame 与 FD 状态原样
    // 保留（提交段只发布已备齐的对象，不再分配）。
    let mut cmdline = alloc::vec::Vec::new();
    for arg in &argv {
        cmdline
            .try_reserve_exact(arg.len() + 1)
            .map_err(|_| Errno::NoMem)?;
        cmdline.extend_from_slice(arg.as_bytes());
        cmdline.push(0);
    }
    // 规范化可执行路径（/proc/self/exe 用）并预分配存储；规范化失败
    // 退化为原始 path，分配失败整体回滚
    // 规范化可执行路径（/proc/self/exe 用）；解析失败意味着原路径无效，
    // execve 本身应失败（Linux 语义：路径解析错误不吞掉）
    let exe_value = {
        let reg = REGISTRY.lock();
        let ctx = reg
            .group(pid)
            .and_then(|r| r.fs.as_ref())
            .ok_or(Errno::Invalid)?;
        ctx.path((-100isize) as usize, &path)?
    };
    let mut locked = REGISTRY.lock();
    let reg = &mut *locked;
    let index = reg.group_index(pid).ok_or(Errno::Invalid)?;
    let rec = &mut reg.records[index];
    if let Some(old) = rec.space.as_ref() {
        space.check_exec_limits().map_err(|_| Errno::NoMem)?;
        old.as_space().deactivate();
    }
    // —— 提交段：发布备齐对象，无分配、无失败路径 ——
    rec.space = Some(LocalSpace(space));
    rec.signal.reset_for_exec();
    if let Some(thread) = reg.threads.iter_mut().find(|t| t.tid == pid) {
        thread.signal.reset_for_exec();
    }
    rec.did_exec = true;
    crate::task::proc_table_set_cmdline(pid, cmdline);
    if let Some(ctx) = rec.fs.as_mut() {
        context::close_exec(ctx);
        // /proc/self/exe 记录（proc(5)）；值为空串时退化为 ENOENT
        ctx.set_exe_path_owned(exe_value);
    }
    *frame = next;
    drop(locked);
    super::sched::wake_vfork(pid);
    Ok(())
}

fn require_random(random: Option<[u8; 16]>) -> Result<[u8; 16], Errno> {
    random.ok_or(Errno::Io)
}

#[cfg(debug_assertions)]
pub(crate) fn self_test() {
    assert_eq!(require_random(None), Err(Errno::Io));
    assert!(require_random(Some([0; 16])).is_ok());
}
