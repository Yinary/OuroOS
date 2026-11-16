//! loongarch64 用户非对齐整数访存模拟：按用户映射权限取指、读写数据。
//! 参考来源：PolyHAL https://github.com/Byte-OS/polyhal polyhal-trap 0.4.0 src/trap/loongarch64/unaligned.rs
//! 原协议：MIT
//! 修改说明：保留原整数指令解码范围，改由 OuroOS 用户访问接口完成访存。
#![deny(unsafe_code)]

use polyhal_trap::trapframe::TrapFrame;

#[cfg(debug_assertions)]
use crate::mm::{
    address_space::AreaKind,
    frame,
    user_access::{copy_from_user, copy_to_user},
};
use crate::mm::{address_space::UserAddressSpace, user_access};
#[cfg(debug_assertions)]
use polyhal::pagetable::MappingFlags;

use super::{UnalignedError, UserFaultKind};

enum Operation {
    Load { width: usize, signed: bool },
    Store { width: usize },
}

/// 启动时直接自检非对齐模拟器的访存和异常原子性。
#[cfg(debug_assertions)]
pub(super) fn self_test() {
    const CODE: usize = 0x40_0000;
    const DATA: usize = 0x50_0000;
    const READ_ONLY: usize = 0x60_0000;
    const EDGE: usize = 0x70_0000;
    let baseline = frame::stats();
    {
        let mut space = UserAddressSpace::new().expect("unaligned self-test address space");
        space
            .map_alloc(CODE, MappingFlags::URX)
            .expect("unaligned self-test code page");
        space
            .map_region(DATA, 1, MappingFlags::URW, AreaKind::Anonymous)
            .expect("unaligned self-test data page");
        space
            .map_region(READ_ONLY, 1, MappingFlags::URX, AreaKind::Anonymous)
            .expect("unaligned self-test read-only page");
        space
            .map_region(EDGE, 1, MappingFlags::URW, AreaKind::Anonymous)
            .expect("unaligned self-test edge page");

        // 指令编码使用模拟器支持的 ld.d、ld.w 和 st.d 操作码字段，rd 位于低五位。
        let store = (0xa7u32 << 22) | 5;
        let load_word = (0xa2u32 << 22) | 6;
        let load_double = (0xa3u32 << 22) | 0;
        let load_read_only = (0xa3u32 << 22) | 7;
        let instructions = [store, load_word, load_double, load_read_only];
        let mut code = [0u8; 16];
        for (slot, instruction) in code.chunks_exact_mut(4).zip(instructions) {
            slot.copy_from_slice(&instruction.to_le_bytes());
        }
        space
            .init_elf_page(CODE, &code)
            .expect("initialize unaligned self-test instructions");

        let mut frame = TrapFrame::new();
        frame.era = CODE;
        frame.regs[5] = 0x8877_6655_4433_2211;
        emulate_unaligned(&mut frame, &space, DATA + 1).expect("unaligned store");
        assert_eq!(frame.era, CODE + 4);
        let mut stored = [0u8; 8];
        copy_from_user(&space, DATA + 1, &mut stored).expect("read unaligned store result");
        assert_eq!(stored, frame.regs[5].to_le_bytes());

        space
            .init_elf_page(CODE + 4, &load_word.to_le_bytes())
            .expect("initialize signed-load instruction");
        copy_to_user(&space, DATA + 0x21, &[0x80, 0xff, 0xff, 0xff])
            .expect("initialize signed-load data");
        frame.era = CODE + 4;
        emulate_unaligned(&mut frame, &space, DATA + 0x21).expect("signed unaligned load");
        assert_eq!(frame.regs[6], (-128isize) as usize);

        space
            .init_elf_page(CODE + 8, &load_double.to_le_bytes())
            .expect("initialize zero-register load instruction");
        frame.era = CODE + 8;
        frame.regs[0] = usize::MAX;
        emulate_unaligned(&mut frame, &space, DATA + 1).expect("load to zero register");
        assert_eq!(frame.regs[0], usize::MAX);

        space
            .init_elf_page(CODE + 12, &store.to_le_bytes())
            .expect("initialize failing-store instruction");
        let edge_data = [0x11, 0x22, 0x33, 0x44];
        copy_to_user(&space, EDGE + 0xffc, &edge_data).expect("initialize edge data");
        frame.era = CODE + 12;
        frame.regs[5] = 0xaabb_ccdd_eeff_0011;
        let old_frame = frame;
        assert!(matches!(
            emulate_unaligned(&mut frame, &space, EDGE + 0xffc),
            Err(UnalignedError::Fault(UserFaultKind::StorePageFault))
        ));
        assert_eq!(frame.era, old_frame.era);
        assert_eq!(frame.regs, old_frame.regs);
        let mut edge_after = [0u8; 4];
        copy_from_user(&space, EDGE + 0xffc, &mut edge_after).expect("read edge data");
        assert_eq!(edge_after, edge_data);

        frame.era = CODE + 12;
        let mut before_read_only = [0u8; 8];
        copy_from_user(&space, READ_ONLY + 1, &mut before_read_only)
            .expect("read read-only mapping before store");
        let old_era = frame.era;
        assert!(matches!(
            emulate_unaligned(&mut frame, &space, READ_ONLY + 1),
            Err(UnalignedError::Fault(UserFaultKind::StorePageFault))
        ));
        assert_eq!(frame.era, old_era);
        let mut after_read_only = [0u8; 8];
        copy_from_user(&space, READ_ONLY + 1, &mut after_read_only)
            .expect("read read-only mapping after store");
        assert_eq!(after_read_only, before_read_only);
    }
    assert_eq!(
        frame::stats(),
        baseline,
        "unaligned self-test leaked frames"
    );
}

fn decode(ins: u32) -> Option<Operation> {
    let op10 = ins >> 22;
    let op8 = ins >> 24;
    let op17 = ins >> 15;
    match (op10, op8, op17) {
        (0xa3, _, _) | (_, 0x26, _) | (_, _, 0x7018) => Some(Operation::Load {
            width: 8,
            signed: true,
        }),
        (0xa2, _, _) | (_, 0x24, _) | (_, _, 0x7010) => Some(Operation::Load {
            width: 4,
            signed: true,
        }),
        (0xaa, _, _) | (_, _, 0x7050) => Some(Operation::Load {
            width: 4,
            signed: false,
        }),
        (0xa1, _, _) | (_, _, 0x7048) => Some(Operation::Load {
            width: 2,
            signed: true,
        }),
        (0xa9, _, _) | (_, _, 0x7008) => Some(Operation::Load {
            width: 2,
            signed: false,
        }),
        (0xa7, _, _) | (_, 0x27, _) | (_, _, 0x7038) => Some(Operation::Store { width: 8 }),
        (0xa6, _, _) | (_, 0x25, _) | (_, _, 0x7030) => Some(Operation::Store { width: 4 }),
        (0xa5, _, _) | (_, _, 0x7028) => Some(Operation::Store { width: 2 }),
        _ => None,
    }
}

/// 模拟一条用户非对齐整数访存指令；成功推进 ERA 4 字节。
/// 失败时不修改 TrapFrame，写入由 user_access 整段预检保证原子性。
pub fn emulate_unaligned(
    frame: &mut TrapFrame,
    space: &UserAddressSpace,
    addr: usize,
) -> Result<(), UnalignedError> {
    let mut ins = [0u8; 4];
    user_access::copy_user_instruction(space, frame.era, &mut ins)
        .map_err(|_| UnalignedError::Fault(UserFaultKind::InstructionPageFault))?;
    let ins = u32::from_le_bytes(ins);
    let op = decode(ins).ok_or(UnalignedError::Unsupported)?;
    let rd = (ins & 0x1f) as usize;
    let next_pc = frame
        .era
        .checked_add(4)
        .ok_or(UnalignedError::Unsupported)?;
    match op {
        Operation::Load { width, signed } => {
            let mut bytes = [0u8; 8];
            user_access::copy_from_user(space, addr, &mut bytes[..width])
                .map_err(|_| UnalignedError::Fault(UserFaultKind::LoadPageFault))?;
            let value = match (width, signed) {
                (2, true) => i16::from_le_bytes([bytes[0], bytes[1]]) as i64 as usize,
                (2, false) => u16::from_le_bytes([bytes[0], bytes[1]]) as usize,
                (4, true) => {
                    i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as i64 as usize
                }
                (4, false) => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize,
                (8, _) => u64::from_le_bytes(bytes) as usize,
                _ => unreachable!(),
            };
            if rd != 0 {
                frame.regs[rd] = value;
            }
        }
        Operation::Store { width } => {
            let value = if rd == 0 { 0 } else { frame.regs[rd] };
            user_access::copy_to_user(space, addr, &(value as u64).to_le_bytes()[..width])
                .map_err(|_| UnalignedError::Fault(UserFaultKind::StorePageFault))?;
        }
    }
    frame.era = next_pc;
    Ok(())
}
