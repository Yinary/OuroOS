//! Directory creation, lookup, and bootstrap helpers.

mod bootstrap;
mod insert;
mod lookup;
mod mkdir;
mod path;
mod read;

pub use bootstrap::{create_lost_found_directory, create_root_directory_entry};
pub use insert::insert_dir_entry;
pub(crate) use insert::no_space_before_insert;
pub use lookup::get_inode_with_num;
pub(crate) use mkdir::ensure_directory;
pub use mkdir::{mkdir, mkdir_with_owner};
// OuroOS patch: create a directory by parent inode.
pub use mkdir::mkdir_in_parent;
pub use path::{normalize_path, split_paren_child_and_translatevalid};
// OuroOS patch: read directory records separately from file data.
pub use read::read_dir_at;
