//! Inode metadata update helpers and path-based metadata APIs.
// OuroOS patch: 导出按 inode 更新时间接口，见 README.md。

mod api;
mod apply;
mod inode;
mod time;
mod types;

pub use api::{chmod, chown, set_flags, set_project, utimens, utimens_inode};
pub(crate) use types::{
    Ext4DtimeUpdate, Ext4InodeMetadataUpdate, Ext4MetadataReason, Ext4ModeUpdate,
};
