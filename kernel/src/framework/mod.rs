//! 文件系统所需的底层能力入口。

pub(crate) mod block;

/// 用户复制由 MM 校验地址和权限，调用期间映射须保持稳定。
pub(crate) mod user_access {
    pub(crate) use crate::mm::{address_space::UserAddressSpace, user_access::*};
}
