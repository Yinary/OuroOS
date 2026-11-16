//! File and inode data operations.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use log::{debug, error, info, warn};

use crate::{
    blockdev::*,
    bmalloc::{AbsoluteBN, InodeNumber},
    checksum::update_ext4_dirblock_csum32,
    config::*,
    dir::*,
    disknode::*,
    entries::*,
    error::*,
    ext4::*,
    extents_tree::*,
    loopfile::*,
    metadata::{Ext4DtimeUpdate, Ext4InodeMetadataUpdate},
    superblock::Ext4Superblock,
};

mod blocks;
mod create;
mod delete;
mod io;
mod link;
mod rename;

pub use blocks::build_file_block_mapping_with_inode_num;
pub use create::{create_symbol_link, create_symbol_link_with_owner, mkfile, mkfile_with_owner};
// OuroOS patch: create a regular file by parent inode.
pub use create::create_regular_inode;
pub use delete::{
    delete_dir, delete_file, free_inode, is_dir_empty, remove_inodeentry_from_parentdir, unlink,
};
// OuroOS patch: separate directory-entry removal from inode reclamation.
pub use delete::unlink_regular_entry;
// OuroOS patch: reuse directory-entry lookup for mkdir.
pub(crate) use delete::find_named_entry_in_parent;
pub use io::{
    read_file, read_inode_data_into, truncate, truncate_inode, write_file, write_inode_data,
};
pub use link::link;
pub use rename::{mv, rename};
