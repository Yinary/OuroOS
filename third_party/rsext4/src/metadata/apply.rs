//! Filesystem-side metadata application helpers.

use super::{Ext4DtimeUpdate, Ext4InodeMetadataUpdate, Ext4MetadataReason};
use crate::{
    blockdev::{BlockDevice, Jbd2Dev},
    bmalloc::InodeNumber,
    disknode::{Ext4Inode, Ext4TimeSpec},
    error::{Ext4Error, Ext4Result},
    ext4::Ext4FileSystem,
    superblock::Ext4Superblock,
};

impl Ext4FileSystem {
    pub(crate) fn finalize_inode_update<B: BlockDevice>(
        &mut self,
        device: &mut Jbd2Dev<B>,
        inode_num: InodeNumber,
        inode: &mut Ext4Inode,
        update: Ext4InodeMetadataUpdate,
    ) -> Ext4Result<()> {
        self.apply_loaded_inode_metadata(device, inode, update)?;
        let updated = *inode;
        self.modify_inode(device, inode_num, |on_disk| *on_disk = updated)
    }

    pub(crate) fn apply_inode_metadata<B: BlockDevice>(
        &mut self,
        device: &mut Jbd2Dev<B>,
        inode_num: InodeNumber,
        update: Ext4InodeMetadataUpdate,
    ) -> Ext4Result<Ext4Inode> {
        let mut inode = self.get_inode_by_num(device, inode_num)?;
        self.finalize_inode_update(device, inode_num, &mut inode, update)?;
        Ok(inode)
    }

    pub(crate) fn apply_inode_flags<B: BlockDevice>(
        &mut self,
        device: &mut Jbd2Dev<B>,
        inode_num: InodeNumber,
        flags: u32,
    ) -> Ext4Result<Ext4Inode> {
        if flags & !Ext4Inode::EXT4_FL_USER_VISIBLE != 0 {
            return Err(Ext4Error::invalid_input());
        }

        let mut inode = self.get_inode_by_num(device, inode_num)?;
        let modifiable = Ext4Inode::mask_flags_for_mode(
            inode.i_mode,
            flags & Ext4Inode::EXT4_FL_USER_MODIFIABLE,
        );
        let preserved = inode.i_flags & !Ext4Inode::EXT4_FL_USER_MODIFIABLE;
        inode.i_flags = preserved | modifiable;
        self.finalize_inode_update(
            device,
            inode_num,
            &mut inode,
            Ext4InodeMetadataUpdate {
                reason: Ext4MetadataReason::Flags,
                ctime: Some(Ext4TimeSpec::Now),
                ..Default::default()
            },
        )?;
        Ok(inode)
    }

    pub(crate) fn apply_inode_project<B: BlockDevice>(
        &mut self,
        device: &mut Jbd2Dev<B>,
        inode_num: InodeNumber,
        projid: u32,
    ) -> Ext4Result<Ext4Inode> {
        if !self
            .superblock
            .has_feature_ro_compat(Ext4Superblock::EXT4_FEATURE_RO_COMPAT_PROJECT)
        {
            return Err(Ext4Error::unsupported());
        }

        let mut inode = self.get_inode_by_num(device, inode_num)?;
        self.ensure_extra_isize_for_field(&mut inode, Ext4Inode::FIELD_END_I_PROJID)?;
        inode.i_projid = projid;
        self.finalize_inode_update(
            device,
            inode_num,
            &mut inode,
            Ext4InodeMetadataUpdate {
                reason: Ext4MetadataReason::Project,
                ctime: Some(Ext4TimeSpec::Now),
                ..Default::default()
            },
        )?;
        Ok(inode)
    }

    pub(crate) fn apply_inode_dtime<B: BlockDevice>(
        &mut self,
        device: &mut Jbd2Dev<B>,
        inode_num: InodeNumber,
        dtime: Ext4DtimeUpdate,
    ) -> Ext4Result<Ext4Inode> {
        let mut inode = self.get_inode_by_num(device, inode_num)?;
        self.finalize_inode_update(
            device,
            inode_num,
            &mut inode,
            Ext4InodeMetadataUpdate {
                reason: Ext4MetadataReason::LinkCount,
                dtime,
                ..Default::default()
            },
        )?;
        Ok(inode)
    }

    pub(crate) fn touch_inode_atime_if_needed<B: BlockDevice>(
        &mut self,
        device: &mut Jbd2Dev<B>,
        inode_num: InodeNumber,
    ) -> Ext4Result<()> {
        // OuroOS patch: a read-only mount cannot update access time.
        if self.readonly {
            return Ok(());
        }
        let inode = self.get_inode_by_num(device, inode_num)?;
        self.touch_inode_atime_if_needed_loaded(device, inode_num, &inode)
    }

    // OuroOS patch: 复用已加载的 inode 做 relatime 判定（Linux mount(8) 默认语义），
    // 避免高频小读重复查找 inode 表、重算 CRC32C 与标脏。
    pub(crate) fn touch_inode_atime_if_needed_loaded<B: BlockDevice>(
        &mut self,
        device: &mut Jbd2Dev<B>,
        inode_num: InodeNumber,
        inode: &Ext4Inode,
    ) -> Ext4Result<()> {
        if self.readonly || inode.i_flags & Ext4Inode::EXT4_NOATIME_FL != 0 {
            return Ok(());
        }
        let inode_size = self.superblock.s_inode_size;
        let atime = inode.atime_ts(inode_size);
        let mtime = inode.mtime_ts(inode_size);
        let ctime = inode.ctime_ts(inode_size);
        let now = device.current_time()?;
        let older_than_mod =
            (atime.sec, atime.nsec) <= (mtime.sec, mtime.nsec)
                || (atime.sec, atime.nsec) <= (ctime.sec, ctime.nsec);
        let stale = now.sec.saturating_sub(atime.sec) >= 86_400;
        if !older_than_mod && !stale {
            return Ok(());
        }

        let _ =
            self.apply_inode_metadata(device, inode_num, Ext4InodeMetadataUpdate::read_access())?;
        Ok(())
    }

    pub(crate) fn touch_parent_dir_for_entry_change<B: BlockDevice>(
        &mut self,
        device: &mut Jbd2Dev<B>,
        inode_num: InodeNumber,
    ) -> Ext4Result<()> {
        let _ = self.apply_inode_metadata(
            device,
            inode_num,
            Ext4InodeMetadataUpdate::parent_dir_change(),
        )?;
        Ok(())
    }

    pub(crate) fn touch_inode_ctime_for_link_change<B: BlockDevice>(
        &mut self,
        device: &mut Jbd2Dev<B>,
        inode_num: InodeNumber,
    ) -> Ext4Result<()> {
        let _ = self.apply_inode_metadata(
            device,
            inode_num,
            Ext4InodeMetadataUpdate::link_count_change(),
        )?;
        Ok(())
    }

    pub(crate) fn set_inode_links_count<B: BlockDevice>(
        &mut self,
        device: &mut Jbd2Dev<B>,
        inode_num: InodeNumber,
        links_count: u16,
    ) -> Ext4Result<Ext4Inode> {
        let mut inode = self.get_inode_by_num(device, inode_num)?;
        inode.i_links_count = links_count;
        self.finalize_inode_update(
            device,
            inode_num,
            &mut inode,
            Ext4InodeMetadataUpdate::link_count_change(),
        )?;
        Ok(inode)
    }
}
