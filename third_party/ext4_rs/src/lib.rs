// OuroOS patch: core::error 已稳定，不需要 feature 开关。
#![no_std]
#![allow(unused)]

extern crate alloc;

pub mod utils;
pub mod prelude;

pub use utils::*;
pub use prelude::*;


mod ext4_defs;
mod ext4_impls;


pub mod simple_interface;
pub mod fuse_interface;


pub use simple_interface::*;
pub use fuse_interface::*;
