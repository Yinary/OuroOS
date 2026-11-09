//! 启动期内存不变量自检，不依赖用户程序名/测例参数。
//! 覆盖页所有权、区间分裂、权限、边界及释放守恒；debug 内核额外逐点注入 OOM。
use super::{
    address_space::{phys_to_kernel_vaddr, AreaKind, MapError, UserAddressSpace, USER_TOP},
    frame,
    user_access::{copy_from_user, copy_to_user},
};
use polyhal::pagetable::{MappingFlags as F, PAGE_SIZE};

/// 自检：页所有权、区间分裂、权限、边界与释放守恒（每次启动；
/// debug 构建额外逐点注入 OOM，见模块头）。
pub(super) fn run() {
    let baseline = frame::stats();
    assert!(matches!(
        frame::frame_alloc(0),
        Err(frame::FrameError::InvalidCount)
    ));
    assert!(matches!(
        frame::frame_alloc(usize::MAX),
        Err(frame::FrameError::InvalidCount)
    ));
    let run = frame::frame_alloc(3).expect("contiguous allocation");
    assert_eq!(frame::stats().1, baseline.1 - 3);
    for i in 0..3 {
        // SAFETY: 本测试独占连续申请的三页，未映射，每页只释放一次。
        unsafe {
            frame::frame_dealloc(polyhal::PhysAddr::new(run.raw() + i * PAGE_SIZE));
        }
    }
    assert_eq!(frame::stats(), baseline);
    #[cfg(debug_assertions)]
    {
        frame::set_test_budget(Some(0));
        assert!(matches!(
            UserAddressSpace::new(),
            Err(MapError::OutOfMemory)
        ));
        frame::set_test_budget(None);
        assert_eq!(frame::stats(), baseline);
    }
    {
        let mut space = UserAddressSpace::new().expect("mm self-test root");
        let root_only = frame::stats();
        space
            .map_region(0x60_0000, 1, F::URW, AreaKind::Anonymous)
            .expect("anonymous region");
        space.unmap(0x60_0000, 1).expect("anonymous release");
        assert_eq!(frame::stats(), root_only);
        space
            .map_region(0x20_0000, 3, F::URW, AreaKind::Heap)
            .expect("mm self-test mapping");
        let mapped = frame::stats();
        assert_eq!(
            space.protect(0x20_0000, 1, F::URW),
            Err(MapError::UnsupportedPermissions)
        );
        assert!(space
            .translate(0x20_0000)
            .expect("actual permissions")
            .1
            .contains(F::X));
        assert_eq!(
            space.map_region(0x20_0000, 1, F::URW, AreaKind::Heap),
            Err(MapError::Overlap)
        );
        assert_eq!(
            space.map_region(usize::MAX - 4095, 1, F::URW, AreaKind::Heap),
            Err(MapError::OutOfUserRange)
        );
        assert!(space.translate(USER_TOP).is_none());
        assert_eq!(frame::stats(), mapped);
        let pa = space.translate(0x20_0000).expect("mapped translation").0;
        // SAFETY: pa 是本空间持有的完整数据页，未进入用户态，无并发访问。
        let bytes = unsafe {
            core::slice::from_raw_parts(phys_to_kernel_vaddr(pa) as *const u8, PAGE_SIZE)
        };
        assert!(bytes.iter().all(|b| *b == 0));
        space.protect(0x20_1000, 1, F::URX).expect("mm protect");
        assert_eq!(space.areas().len(), 3);
        assert!(!space
            .translate(0x20_1000)
            .expect("read-only")
            .1
            .contains(F::W));
        space.protect(0x20_1000, 1, F::U).expect("mm PROT_NONE");
        assert!(space.translate(0x20_1000).is_none());
        space.unmap(0x20_0000, 1).expect("mm partial unmap");
        space
            .protect(0x20_1000, 1, F::URWX)
            .expect("mm restore permission");
        assert!(space.translate(0x20_1000).is_some());
        assert_eq!(
            space.protect(0x20_0000, 3, F::URX),
            Err(MapError::NotMapped)
        );
        space.unmap(0x20_0000, 3).expect("mm unmap with hole");
        assert_eq!(frame::stats(), root_only);
        assert!(space.areas().is_empty());
        #[cfg(debug_assertions)]
        for budget in 0..5 {
            frame::set_test_budget(Some(budget));
            assert_eq!(
                space.map_region(0x3f_f000, 2, F::URW, AreaKind::Heap),
                Err(MapError::OutOfMemory)
            );
            frame::set_test_budget(None);
            assert_eq!(frame::stats(), root_only);
            assert!(space.translate(0x3f_f000).is_none());
            assert!(space.areas().is_empty());
        }
        // 活动空间销毁也必须先恢复内核根，防止释放当前页表。
        space.activate();
    }
    assert_eq!(frame::stats(), baseline);
    {
        let mut first = UserAddressSpace::new().expect("first isolated space");
        let mut second = UserAddressSpace::new().expect("second isolated space");
        let a = first
            .map_alloc(0x10_0000, F::URW)
            .expect("first private page");
        let b = second
            .map_alloc(0x10_0000, F::URW)
            .expect("second private page");
        assert_ne!(a.raw(), b.raw());
        // SAFETY: 两个空间独占各自数据页，未进入用户态；单字节访问不越界。
        unsafe {
            (phys_to_kernel_vaddr(a) as *mut u8).write_volatile(0x31);
            (phys_to_kernel_vaddr(b) as *mut u8).write_volatile(0x72);
            assert_eq!((phys_to_kernel_vaddr(a) as *const u8).read_volatile(), 0x31);
        }
        drop(first);
        assert_eq!(
            second
                .translate(0x10_0000)
                .expect("surviving mapping")
                .0
                .raw(),
            b.raw()
        );
        // SAFETY: second 仍持有 b；释放 first 不得改变该页内容或生命周期。
        unsafe {
            assert_eq!((phys_to_kernel_vaddr(b) as *const u8).read_volatile(), 0x72);
        }
    }
    assert_eq!(frame::stats(), baseline);
    user_copy_tests();
    log::info!("mm self-test: independent address spaces passed");
    log::info!("mm self-test: map/protect/unmap/zeroing/reclaim passed");
    log::info!("mm self-test: user copy read/write passed");
    #[cfg(debug_assertions)]
    log::info!("mm self-test: allocation failure rollback passed");
}

/// 用户内存复制自检：成写、越界、权限、跨页、零长、溢出、内核地址。
fn user_copy_tests() {
    let baseline = frame::stats();
    {
        let mut space = UserAddressSpace::new().expect("copy test space");
        // 前三页连续映射，第三页设为只读；第四页不映射
        space
            .map_region(0x40_0000, 3, F::URW, AreaKind::Heap)
            .expect("rw region");
        space.protect(0x40_2000, 1, F::URX).expect("ro page");

        // 页内写入后读回
        let mut src = [0u8; 16];
        for (i, b) in src.iter_mut().enumerate() {
            *b = i as u8 + 1;
        }
        assert!(copy_to_user(&space, 0x40_0010, &src).is_ok());
        let mut got = [0u8; 16];
        assert!(copy_from_user(&space, 0x40_0010, &mut got).is_ok());
        assert_eq!(got, src);

        // 起始不对齐且跨页写入
        let cross = [0xA5u8; 32];
        assert!(copy_to_user(&space, 0x40_0ff0, &cross).is_ok());
        let mut tail = [0u8; 32];
        assert!(copy_from_user(&space, 0x40_0ff0, &mut tail).is_ok());
        assert_eq!(tail, cross);

        // 只读页写失败、只读页读成功、未映射页读写失败
        assert!(copy_to_user(&space, 0x40_2000, &src).is_err());
        assert!(copy_to_user(&space, 0x40_3000, &src).is_err());
        assert!(copy_from_user(&space, 0x40_2000, &mut got).is_ok());
        assert!(copy_from_user(&space, 0x40_3000, &mut got).is_err());

        // 零长度、溢出、内核地址
        assert!(copy_to_user(&space, 0x40_0000, &[]).is_ok());
        assert!(copy_to_user(&space, usize::MAX, &src).is_err());
        assert!(copy_to_user(&space, 0xffff_ffc0_8020_0000, &src).is_err());
        assert!(copy_from_user(&space, 0xffff_ffc0_8020_0000, &mut got).is_err());

        // 原子性：跨入只读页的写入失败后，之前页内容不变
        let mut edge = [0u8; 8];
        assert!(copy_from_user(&space, 0x40_0ffe, &mut edge).is_ok());
        let mut wide = [0u8; 0x1004];
        assert!(copy_from_user(&space, 0x40_0ffe, &mut wide).is_ok());
        assert!(copy_to_user(&space, 0x40_0ffe, &[0xFFu8; 0x1004]).is_err());
        let mut after = [0u8; 0x1004];
        assert!(copy_from_user(&space, 0x40_0ffe, &mut after).is_ok());
        assert_eq!(after, wide);
    }
    assert_eq!(frame::stats(), baseline);
}
