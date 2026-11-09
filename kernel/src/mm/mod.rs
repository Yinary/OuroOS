//! 内存子系统入口：物理区间 → 唯一所有权帧 → 页表 → 用户虚拟区域。
//!
//! 当前不在中断处理内分配，不做跨核共享地址空间；页表操作使用本核全量
//! TLB 刷新。新增调度/共享地址空间前必须加入活动核集合及远端失效协议。
//!
//! 总体设计与后续接入约定：
//! - 2026-11-07 团队明确不实现 NX，两架构可访问页均可执行。区域保留请求
//!   权限，translate 报告实际权限；protect 对非空权限中缺少 X 的请求返回
//!   UnsupportedPermissions。PROT_NONE 保留整页不可访问语义。
//! - region 是唯一物理内存输入：原始 FDT RAM 不能绕过 HAL 启动保留区登记。
//!   账本不修改分配策略，实际帧管理与区间发现解耦。
//! - frame 只管理物理页，OwnedFrame 是唯一释放凭证；数据页和页表页各有
//!   自己的拥有者，不按 PTE 猜测数据页释放责任。位图管理信息启动后不增长。
//! - page_table 只处理硬件机制，arch 集中 PTE/CSR 差异；不识别 ELF、堆或文件。
//!   保留现有内核直映，用户统一 4 KiB。暂不使用 ASID，切换/撤权用全量刷新。
//! - address_space 维护 VmArea（用途/期望权限）和实际数据页清单。PROT_NONE
//!   保留区域和物理页，以无效的软件标记占据叶槽；恢复权限无需再次分配。
//! - 所有映射修改先验证区间并准备元数据；映射失败撤销本次新页，中间页表
//!   分配失败在发布 PTE 前返回。unmap/protect 的区间拆分失败不修改旧状态。
//! - brk 接入时维护字节级 current_break，页级映射用 Heap 区域；失败返回原
//!   break。mmap 用 Anonymous 区域并寻找空洞；MAP_FIXED 要先预备替换所需
//!   的页和元数据，再原子替换，不能先 unmap 后发现 OOM。当前接口拒绝重叠，
//!   尚未提供 MAP_FIXED 事务或 mmap/brk 系统调用。
//! - fork 首版深拷贝私有页，新空间构建成功后才向调度器发布；不引入 COW。
//!   exec 同样先加载新空间及 argc/argv/envp/auxv，成功才切换并释放旧空间。
//! - copy_to_user/read_user_bytes 必须同时检查区域/实际页权限，不能直接
//!   解引用用户地址；未来并发 munmap 时需持有空间锁或固定被访问页。
//! - 内核栈需要独立的虚拟映射窗口与底部保护页，不能在直映上仅留一页
//!   “不分配”冒充保护。该窗口涉及 RV 内核共享页表与 LA PGDH，后续和调度
//!   模块单独接入；本轮只实现用户空间页表，不声称已有受保护内核栈。
//! - 逐步实现顺序：本层不变量 → brk/匿名 mmap → fork/exec → 文件映射；
//!   按需分页、COW、页缓存、swap、共享地址空间的远端 TLB 同步暂不实现。
//! - 当前固定 8 MiB 内核堆不扩容；MM 元数据使用 try_reserve 返回 OOM，
//!   帧分配/归还不再依赖运行期堆分配。其他子系统的堆耗尽策略不由 MM 代替。
pub mod address_space;
mod arch;
pub mod frame;
pub mod kernel_pt;
pub mod kstack;
mod page_table;
pub mod region;
mod self_test;
pub mod user_access;
use core::sync::atomic::{AtomicUsize, Ordering};
static KERNEL_ROOT: AtomicUsize = AtomicUsize::new(0);

/// 初始化一次，先完成物理记账，再运行启动期内存自检。
/// 引导数据不可用或元数据分配失败是启动失败，不属于用户系统调用路径。
pub fn init() {
    region::init().expect("physical memory initialization failed");
    let (total, free) = frame::stats();
    assert!(total > 0, "no usable physical memory");
    log::info!(
        "frame allocator: {} pages free / {} registered",
        free,
        total
    );
    // 自检：帧账本守恒——超量申请被拒且不改变空闲数（每次启动）
    assert_eq!(
        frame::frame_alloc(free + 1),
        Err(frame::FrameError::OutOfMemory)
    );
    assert_eq!(frame::stats(), (total, free));
    log::info!("frame allocator oversized allocation: rejected without changing free pages");
    // 顺序约束：kernel_pt::init 先于 KERNEL_ROOT 读取
    kernel_pt::init();
    KERNEL_ROOT.store(arch::current(), Ordering::Relaxed);
    self_test::run();
}
/// 经内核别名写入用户代码后同步指令缓存。PolyHAL 未提供对应封装。
pub fn fence_icache() {
    // SAFETY: 当前运行在内核特权态；指令不访问 Rust 内存，无寄存器破坏。
    unsafe {
        #[cfg(target_arch = "riscv64")]
        core::arch::asm!("fence.i");
        #[cfg(target_arch = "loongarch64")]
        core::arch::asm!("ibar 0");
    }
}
