//! 启动期内存不变量自检，不依赖用户程序名/测例参数。
//! 覆盖页所有权、区间分裂、权限、边界及释放守恒；debug 内核额外逐点注入 OOM。
use super::{
    address_space::{
        phys_to_kernel_vaddr, AreaKind, MapError, UserAddressSpace, USER_STACK_TOP, USER_TOP,
    },
    frame,
    kstack::WINDOW_ROOT_START,
    user_access::{copy_from_user, copy_to_user},
};
use polyhal::pagetable::{MappingFlags as F, PAGE_SIZE};

/// 自检：页所有权、区间分裂、权限、边界与释放守恒（每次启动；
/// debug 构建额外逐点注入 OOM，见模块头）。
pub(super) fn run() {
    #[cfg(debug_assertions)]
    super::kstack::check();
    #[cfg(debug_assertions)]
    crate::elf::self_test();
    #[cfg(debug_assertions)]
    crate::syscall::memory_self_test();
    #[cfg(debug_assertions)]
    crate::task::exec_self_test();
    #[cfg(debug_assertions)]
    {
        let frame = crate::mm::frame::FrameRef::new().expect("frame ref test");
        assert_eq!(frame.strong_count(), 1);
        let clone = frame.clone();
        assert_eq!(frame.strong_count(), 2);
        drop(clone);
        assert_eq!(frame.strong_count(), 1);
        for n in 0..PAGE_SIZE / 32 {
            frame.write(n * 32, &[n as u8; 32]).unwrap();
        }
        let private = frame.duplicate().expect("copy whole frame");
        assert_ne!(private.addr(), frame.addr());
        for n in 0..PAGE_SIZE / 32 {
            let mut chunk = [0xff; 32];
            private.read(n * 32, &mut chunk).unwrap();
            assert_eq!(chunk, [n as u8; 32]);
        }
    }
    {
        let baseline = frame::stats();
        let mut space = UserAddressSpace::new().expect("lazy root");
        let root_only = frame::stats();
        space
            .reserve_region(0x400000, 1024, F::URW, AreaKind::Anonymous)
            .expect("lazy reservation");
        assert_eq!(frame::stats(), root_only);
        assert_eq!(space.resident(0x400000), Ok(false));
        #[cfg(debug_assertions)]
        for budget in 0..3 {
            frame::set_test_budget(Some(budget));
            assert_eq!(
                space.ensure_access(0x400000, F::U | F::W),
                Err(MapError::OutOfMemory)
            );
            frame::set_test_budget(None);
            assert_eq!(frame::stats(), root_only);
            assert_eq!(space.resident(0x400000), Ok(false));
        }
        copy_to_user(&space, 0x400000, &[23]).expect("lazy kernel write");
        assert_eq!(space.resident(0x400000), Ok(true));
        let child = space.deep_copy().expect("lazy clone");
        assert_eq!(child.resident(0x401000), Ok(false));
        space.advise(0x400000, 1, true).expect("actual discard");
        assert_eq!(space.resident(0x400000), Ok(false));
        let mut byte = [99];
        copy_from_user(&space, 0x400000, &mut byte).expect("lazy zero refill");
        assert_eq!(byte, [0]);
        copy_from_user(&child, 0x400000, &mut byte).expect("clone retained");
        assert_eq!(byte, [23]);
        space.protect(0x401000, 1, F::U).expect("unresident none");
        assert_eq!(
            space.ensure_access(0x401000, F::U | F::R),
            Err(MapError::PermissionDenied)
        );
        space
            .reserve_fixed(0x400000, 2, F::URW)
            .expect("fixed lazy replacement");
        assert_eq!(space.resident(0x400000), Ok(false));
        copy_from_user(&space, 0x400000, &mut byte).expect("fixed zero");
        assert_eq!(byte, [0]);
        drop(child);
        drop(space);
        assert_eq!(frame::stats(), baseline);
    }
    {
        let mut space = UserAddressSpace::new().expect("lock root");
        space
            .reserve_region(0x900000, 3, F::URW, AreaKind::Anonymous)
            .expect("lock area");
        space
            .lock_range(0x900000, 2, true, true)
            .expect("onfault lock");
        assert_eq!(space.resident(0x900000), Ok(false));
        assert_eq!(
            space.advise(0x900000, 1, true),
            Err(MapError::InvalidPermissions)
        );
        assert_eq!(
            space.sync_range(0x900000, 1, true),
            Err(crate::syscall::Errno::Busy)
        );
        let child = space.deep_copy().expect("lock fork");
        assert!(child.areas().iter().all(|a| !a.locked));
        space
            .lock_range(0x900000, 1, false, false)
            .expect("partial unlock");
        space.advise(0x900000, 1, true).expect("unlocked discard");
        space
            .lock_range(0x900000, 3, true, false)
            .expect("populate lock");
        for va in (0x900000..0x903000).step_by(PAGE_SIZE) {
            assert_eq!(space.resident(va), Ok(true));
        }
        assert_eq!(
            space.lock_range(0x900000, 4, false, false),
            Err(MapError::NotMapped)
        );
        assert!(space.areas().iter().all(|a| a.locked));
        space.unmap(0x900000, 3).expect("locked unmap");
    }
    {
        let mut space = UserAddressSpace::new().expect("advice root");
        space
            .map_region(0x120000, 2, F::URW, AreaKind::Anonymous)
            .expect("advice pages");
        copy_to_user(&space, 0x120000, &[81]).expect("advice data");
        let child = space.deep_copy().expect("advice fork");
        assert_eq!(space.advise(0x120000, 3, true), Err(MapError::NotMapped));
        let mut byte = [0];
        copy_from_user(&space, 0x120000, &mut byte).expect("failure preserves data");
        assert_eq!(byte, [81]);
        space.protect(0x120000, 1, F::U).expect("advice none");
        #[cfg(debug_assertions)]
        frame::set_test_budget(Some(0));
        space
            .advise(0x120000, 2, true)
            .expect("discard without allocation");
        #[cfg(debug_assertions)]
        frame::set_test_budget(None);
        assert!(space.translate(0x120000).is_none());
        space.protect(0x120000, 1, F::URWX).expect("advice restore");
        copy_from_user(&space, 0x120000, &mut byte).expect("zero data");
        assert_eq!(byte, [0]);
        copy_from_user(&child, 0x120000, &mut byte).expect("child private data");
        assert_eq!(byte, [81]);
        space
            .map_shared_anonymous(0x130000, 1, F::URW, false, true)
            .expect("shared advice");
        copy_to_user(&space, 0x130000, &[17]).expect("shared sentinel");
        space
            .advise(0x130000, 1, true)
            .expect("discard shared translation");
        assert!(space.translate(0x130000).is_none());
        copy_from_user(&space, 0x130000, &mut byte).expect("shared preserved");
        assert_eq!(byte, [17]);
    }
    {
        let baseline = frame::stats();
        let mut parent = UserAddressSpace::new().expect("shared root");
        parent
            .map_shared_anonymous(0x90000, 2, F::URW, false, true)
            .expect("shared map");
        copy_to_user(&parent, 0x90000, &[7]).expect("shared initial");
        #[cfg(debug_assertions)]
        frame::set_test_budget(Some(3));
        let mut child = parent
            .deep_copy()
            .expect("shared fork only allocates page tables");
        #[cfg(debug_assertions)]
        frame::set_test_budget(None);
        copy_to_user(&child, 0x90000, &[8]).expect("shared child write");
        let mut byte = [0];
        copy_from_user(&parent, 0x90000, &mut byte).expect("parent view");
        assert_eq!(byte, [8]);
        parent.unmap(0x90000, 2).expect("parent unmap");
        child
            .remap(0x90000, 2, 1, true, Some(0xb0000))
            .expect("shared move");
        copy_from_user(&child, 0xb0000, &mut byte).expect("child survives");
        assert_eq!(byte, [8]);
        drop(child);
        drop(parent);
        assert_eq!(frame::stats(), baseline);
    }
    {
        let baseline = frame::stats();
        let mut space = UserAddressSpace::new().expect("remap root");
        space
            .map_region(0x40000, 2, F::URW, AreaKind::Anonymous)
            .expect("source");
        copy_to_user(&space, 0x40000, &[42]).expect("sentinel");
        space
            .map_region(0x42000, 1, F::URW, AreaKind::Anonymous)
            .expect("blocker");
        assert_eq!(
            space.remap(0x40000, 2, 3, false, None),
            Err(MapError::OutOfMemory)
        );
        #[cfg(debug_assertions)]
        for budget in 0..12 {
            let before = frame::stats();
            frame::set_test_budget(Some(budget));
            let result = space.remap(0x40000, 2, 3, true, Some(0x80000));
            frame::set_test_budget(None);
            if result.is_ok() {
                space
                    .remap(0x80000, 3, 2, true, Some(0x40000))
                    .expect("restore");
            } else {
                assert_eq!(frame::stats(), before);
                assert!(space.translate(0x80000).is_none());
            }
            let mut byte = [0];
            copy_from_user(&space, 0x40000, &mut byte).expect("old data");
            assert_eq!(byte, [42]);
        }
        let dest = space.remap(0x40000, 2, 3, true, None).expect("move");
        assert_ne!(dest, 0x40000);
        assert!(space.translate(0x40000).is_none());
        let mut byte = [0];
        copy_from_user(&space, dest, &mut byte).expect("moved data");
        assert_eq!(byte, [42]);
        assert_eq!(space.resident(dest + 2 * PAGE_SIZE), Ok(false));
        copy_from_user(&space, dest + 2 * PAGE_SIZE, &mut byte).expect("zero extension");
        assert_eq!(byte, [0]);
        space.protect(dest, 1, F::U).expect("none");
        assert_eq!(space.resident(dest), Ok(true));
        assert!(space.translate(dest).is_none());
        space.protect(dest, 1, F::URWX).expect("restore permission");
        space.protect(dest, 3, F::URWX).expect("unify");
        space.remap(dest, 3, 1, false, None).expect("shrink");
        assert_eq!(space.resident(dest + PAGE_SIZE), Err(MapError::NotMapped));
        drop(space);
        assert_eq!(frame::stats(), baseline);
    }
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
        space.protect(0x20_0000, 1, F::URW).expect("mprotect RW");
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
        space
            .protect(0x20_1000, 1, F::U | F::R)
            .expect("mprotect R");
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
    #[cfg(debug_assertions)]
    {
        let mut space = UserAddressSpace::new().expect("fixed test root");
        let pa = space.map_alloc(0x20_0000, F::URW).expect("fixed original");
        // SAFETY: 测试持有数据页，尚无用户并发访问，字节访问在页内。
        unsafe {
            (phys_to_kernel_vaddr(pa) as *mut u8).write_volatile(93);
        }
        let before = frame::stats();
        space.activate();
        // 两个新数据页、根页和两级中间表，共五次帧分配；逐次失败都须回滚。
        for budget in 0..5 {
            frame::set_test_budget(Some(budget));
            assert_eq!(
                space.replace_region(0x20_0000, 2, F::URW),
                Err(MapError::OutOfMemory)
            );
            frame::set_test_budget(None);
            assert_eq!(frame::stats(), before);
            assert_eq!(space.translate(0x20_0000).unwrap().0.raw(), pa.raw());
            // SAFETY: 失败后原页仍归该测试空间所有。
            unsafe {
                assert_eq!((phys_to_kernel_vaddr(pa) as *const u8).read_volatile(), 93);
            }
        }
        space
            .replace_region(0x20_0000, 2, F::URW)
            .expect("fixed commit");
        let fresh = space.translate(0x20_0000).unwrap().0;
        assert_ne!(fresh.raw(), pa.raw());
        // SAFETY: 新匿名页在当前空间内，成功替换后仍持有其所有权。
        unsafe {
            assert_eq!(
                (phys_to_kernel_vaddr(fresh) as *const u8).read_volatile(),
                0
            );
        }
        drop(space);
        assert_eq!(frame::stats(), baseline);
        log::info!("mm self-test: fixed replacement rollback passed");
    }
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

    {
        // COW：fork 后先共享同一物理页，写缺页后才分离。
        let baseline = frame::stats();
        let mut parent = UserAddressSpace::new().expect("cow root");
        parent
            .reserve_region(0x700000, 1, F::URW, AreaKind::Anonymous)
            .expect("cow parent map");
        copy_to_user(&parent, 0x700000, &[0x2a]).expect("cow parent initial");
        let parent_pa = parent.translate(0x700000).expect("cow parent pa").0;
        let child = parent.deep_copy().expect("cow fork");
        assert!(!parent
            .translate(0x700000)
            .expect("cow parent ro")
            .1
            .contains(F::W));
        assert_eq!(
            child.translate(0x700000).expect("cow child pa").0,
            parent_pa
        );
        assert!(!child
            .translate(0x700000)
            .expect("cow child flags")
            .1
            .contains(F::W));
        copy_to_user(&child, 0x700000, &[0x2b]).expect("cow child write");
        assert_ne!(
            child.translate(0x700000).expect("cow child split pa").0,
            parent_pa
        );
        assert!(child
            .translate(0x700000)
            .expect("cow child w")
            .1
            .contains(F::W));
        assert!(!parent
            .translate(0x700000)
            .expect("cow parent ro")
            .1
            .contains(F::W));
        let mut byte = [0];
        copy_from_user(&parent, 0x700000, &mut byte).expect("cow parent read");
        assert_eq!(byte, [0x2a]);
        copy_from_user(&child, 0x700000, &mut byte).expect("cow child read");
        assert_eq!(byte, [0x2b]);
        copy_to_user(&parent, 0x700000, &[0x2c]).expect("cow parent write");
        assert!(parent
            .translate(0x700000)
            .expect("cow parent w")
            .1
            .contains(F::W));
        copy_from_user(&parent, 0x700000, &mut byte).expect("cow parent final");
        assert_eq!(byte, [0x2c]);
        drop(child);
        drop(parent);
        assert_eq!(frame::stats(), baseline);
    }

    #[cfg(debug_assertions)]
    {
        let mut parent = UserAddressSpace::new().expect("fork root");
        // 两端位于不同的末级页表，覆盖活动父表批量撤销写权限的边界。
        let base = 0x7fe000;
        let page = |n: usize| base + n * PAGE_SIZE;
        parent
            .reserve_region(base, 5, F::URW, AreaKind::Anonymous)
            .unwrap();
        for n in [4, 0, 2] {
            copy_to_user(&parent, page(n), &[1]).unwrap();
        }
        parent.activate();
        // 子页表分配中断后，父映射仍可原地写入。
        frame::set_test_budget(Some(2));
        let failed = parent.deep_copy();
        frame::set_test_budget(None);
        assert!(matches!(failed, Err(MapError::OutOfMemory)));
        assert!(parent.translate(page(2)).unwrap().1.contains(F::W));
        let first = parent.deep_copy().unwrap();
        for n in [0, 2, 4] {
            assert!(!parent.translate(page(n)).unwrap().1.contains(F::W));
        }
        copy_to_user(&parent, page(2), &[2]).unwrap();
        copy_to_user(&parent, page(1), &[3]).unwrap();
        let second = parent.deep_copy().unwrap();
        copy_to_user(&parent, page(1), &[4]).unwrap();
        let mut byte = [0];
        for (space, n, expected) in [
            (&first, 2, 1),
            (&first, 1, 0),
            (&second, 2, 2),
            (&second, 1, 3),
            (&parent, 1, 4),
            (&parent, 4, 1),
        ] {
            copy_from_user(space, page(n), &mut byte).unwrap();
            assert_eq!(byte, [expected]);
        }
        parent.deactivate();
    }
    assert_eq!(frame::stats(), baseline);

    #[cfg(debug_assertions)]
    for all in [false, true] {
        let baseline = frame::stats();
        let mut parent = UserAddressSpace::new().expect("lock cow root");
        let va = 0x700000;
        parent
            .reserve_region(va, 2, F::URW, AreaKind::Anonymous)
            .unwrap();
        copy_to_user(&parent, va, &[42]).unwrap();
        copy_to_user(&parent, va + PAGE_SIZE, &[43]).unwrap();
        parent.protect(va + PAGE_SIZE, 1, F::U | F::R).unwrap();
        let mut child = parent.deep_copy().unwrap();
        let lock = |space: &mut UserAddressSpace, on_fault: bool| {
            if all {
                space.lock_all(if on_fault { 5 } else { 1 })
            } else {
                space.lock_range(va, 2, true, on_fault)
            }
        };
        frame::set_test_budget(Some(0));
        let lazy = lock(&mut child, true);
        let eager = lock(&mut child, false);
        frame::set_test_budget(None);
        assert_eq!(lazy, Ok(()));
        assert_eq!(eager, Err(MapError::OutOfMemory), "lock must prepare COW");
        assert_eq!(child.translate(va), parent.translate(va));
        lock(&mut child, false).expect("retry eager lock");
        assert_eq!(
            child.translate(va + PAGE_SIZE),
            parent.translate(va + PAGE_SIZE)
        );
        frame::set_test_budget(Some(0));
        let written = copy_to_user(&child, va, &[99]);
        frame::set_test_budget(None);
        written.expect("write after eager lock");
        let mut byte = [0];
        copy_from_user(&parent, va, &mut byte).unwrap();
        assert_eq!(byte, [42]);
        drop(child);
        drop(parent);
        assert_eq!(frame::stats(), baseline);
    }

    {
        // Stack COW：父先写必须拆页，子仍持有旧帧。
        let baseline = frame::stats();
        let mut parent = UserAddressSpace::new().expect("stack cow root");
        parent.map_stack().expect("stack map");
        let va = USER_STACK_TOP - PAGE_SIZE;
        copy_to_user(&parent, va, &[0x31]).expect("stack initial");
        let parent_pa = parent.translate(va).expect("stack parent pa").0;
        let child = parent.deep_copy().expect("stack cow fork");
        assert_eq!(child.translate(va).expect("stack child pa").0, parent_pa);
        assert!(!parent
            .translate(va)
            .expect("stack parent ro")
            .1
            .contains(F::W));
        assert!(!child
            .translate(va)
            .expect("stack child ro")
            .1
            .contains(F::W));
        copy_to_user(&parent, va, &[0x32]).expect("stack parent first write");
        assert_ne!(
            parent.translate(va).expect("stack parent split").0,
            parent_pa
        );
        let mut byte = [0];
        copy_from_user(&child, va, &mut byte).expect("stack child old");
        assert_eq!(byte, [0x31]);
        copy_to_user(&child, va, &[0x33]).expect("stack child write");
        copy_from_user(&child, va, &mut byte).expect("stack child final");
        assert_eq!(byte, [0x33]);
        copy_from_user(&parent, va, &mut byte).expect("stack parent final");
        assert_eq!(byte, [0x32]);
        drop(child);
        drop(parent);
        assert_eq!(frame::stats(), baseline);
    }

    {
        // 用户地址入口必须拒绝共享内核栈窗口根项。
        assert!(UserAddressSpace::check_user_span(WINDOW_ROOT_START, PAGE_SIZE).is_err());
        let mut space = UserAddressSpace::new().expect("window guard root");
        assert!(space
            .reserve_region(WINDOW_ROOT_START, 1, F::URW, AreaKind::Anonymous)
            .is_err());
        assert!(space.reserve_fixed(WINDOW_ROOT_START, 1, F::URW).is_err());
    }

    {
        // 保留窗口边界：普通映射可紧邻、可跨窗口 munmap，空 ELF 段允许。
        let start = WINDOW_ROOT_START - PAGE_SIZE;
        let mut space = UserAddressSpace::new().expect("window edge root");
        space
            .reserve_region(start, 1, F::URW, AreaKind::Anonymous)
            .expect("window edge mapping");
        assert!(space.unmap(start, 2).is_ok());
        assert!(UserAddressSpace::check_user_span(WINDOW_ROOT_START + PAGE_SIZE, 0).is_ok());
        assert!(space.find_free(0, (16usize << 30) / PAGE_SIZE).is_ok());
    }
}
