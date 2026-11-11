//! execve 的参数复制、初始栈构造和地址空间事务切换。
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
        out.push(context::user_path(space, address)?);
    }
    Err(Errno::TooBig)
}
/// 布置 argc/argv/envp/auxv，栈顶按 16 字节对齐。
pub fn stack(space: &UserAddressSpace, argv: &[String], envp: &[String]) -> Result<usize, Errno> {
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
    let mut words = Vec::new();
    words
        .try_reserve(pointers.len() + 9)
        .map_err(|_| Errno::NoMem)?;
    words.push(argv.len());
    words.extend_from_slice(&pointers[..argv.len()]);
    words.push(0);
    words.extend_from_slice(&pointers[argv.len()..]);
    words.extend_from_slice(&[0, 6, 4096, 0, 0]); // AT_PAGESZ 与 AT_NULL
    sp = sp.checked_sub(words.len() * 8).ok_or(Errno::TooBig)? & !15;
    for (i, word) in words.iter().enumerate() {
        user_access::copy_to_user(space, sp + i * 8, &word.to_ne_bytes())
            .map_err(|_| Errno::TooBig)?;
    }
    Ok(sp)
}
/// 全部准备成功才替换旧地址空间，失败保留原程序和现场。
pub fn exec(pid: Pid, args: [usize; 3], frame: &mut TrapFrame) -> Result<(), Errno> {
    let (image, argv, envp) = {
        let reg = REGISTRY.lock();
        let rec = reg
            .records
            .iter()
            .find(|r| r.pid == pid)
            .ok_or(Errno::Invalid)?;
        let space = rec.space.as_ref().ok_or(Errno::Invalid)?.as_space();
        let path = context::user_path(space, args[0])?;
        let argv = strings(space, args[1])?;
        let envp = strings(space, args[2])?;
        let image = context::executable(rec.fs.as_ref().ok_or(Errno::Invalid)?, &path)?;
        (image, argv, envp)
    };
    let mut space = UserAddressSpace::new().map_err(|_| Errno::NoMem)?;
    let entry = elf::load_elf(&mut space, &image).map_err(|e| {
        if matches!(e, elf::ElfError::OutOfMemory) {
            Errno::NoMem
        } else {
            Errno::ExecFormat
        }
    })?;
    space.init_heap();
    space.map_stack().map_err(|_| Errno::NoMem)?;
    let sp = stack(&space, &argv, &envp)?;
    let mut next = TrapFrame::new();
    next[TrapFrameArgs::SEPC] = entry;
    next[TrapFrameArgs::SP] = sp;
    let mut reg = REGISTRY.lock();
    let rec = reg
        .records
        .iter_mut()
        .find(|r| r.pid == pid)
        .ok_or(Errno::Invalid)?;
    if let Some(old) = rec.space.as_ref() {
        old.as_space().deactivate();
    }
    rec.space = Some(LocalSpace(space));
    if let Some(ctx) = rec.fs.as_mut() {
        context::close_exec(ctx);
    }
    *frame = next;
    Ok(())
}
