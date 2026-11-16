// OuroOS patch: 03-directory-and-descriptor-parsing (see README.md).
//! HTree directory structures and hashing helpers.

use super::Ext4DirEntry2;

/// Root block layout for an HTree directory.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Ext4DxRoot {
    pub dot: Ext4DirEntry2,
    pub dotdot: Ext4DirEntry2,
    pub info: Ext4DxRootInfo,
}

/// HTree root metadata.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Ext4DxRootInfo {
    pub reserved_zero: u32,
    pub hash_version: u8,
    pub info_length: u8,
    pub indirect_levels: u8,
    pub unused_flags: u8,
}

impl Ext4DxRootInfo {
    pub const INFO_LENGTH: u8 = 8;
}

impl Ext4DxRootInfo {
    pub const DX_HASH_LEGACY: u8 = 0;
    pub const DX_HASH_HALF_MD4: u8 = 1;
    pub const DX_HASH_TEA: u8 = 2;
    pub const DX_HASH_LEGACY_UNSIGNED: u8 = 3;
    pub const DX_HASH_HALF_MD4_UNSIGNED: u8 = 4;
    pub const DX_HASH_TEA_UNSIGNED: u8 = 5;
}

/// HTree index entry.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Ext4DxEntry {
    pub hash: u32,
    pub block: u32,
}

/// Entry count and limit header used by HTree blocks.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Ext4DxCountlimit {
    pub limit: u16,
    pub count: u16,
}

/// Full HTree node header.
#[repr(C)]
#[derive(Debug)]
pub struct Ext4DxNode {
    pub fake: Ext4DirEntry2,
    pub countlimit: Ext4DxCountlimit,
}

/// Calculates a directory hash for an HTree directory.
pub fn calculate_hash(name: &[u8], hash_version: u8, hash_seed: &[u32; 4]) -> u32 {
    match hash_version {
        Ext4DxRootInfo::DX_HASH_LEGACY => legacy_hash(name),
        Ext4DxRootInfo::DX_HASH_HALF_MD4 => half_md4_hash(name, hash_seed, true),
        4 => half_md4_hash(name, hash_seed, false),
        Ext4DxRootInfo::DX_HASH_TEA => tea_hash(name, hash_seed),
        _ => 0,
    }
}

fn legacy_hash(name: &[u8]) -> u32 {
    let mut hash = 0u32;
    for &byte in name {
        hash = hash.wrapping_mul(33).wrapping_add(byte as u32);
    }
    hash
}

// MD4 rounds follow RFC 1320, with Ext4's eight-word schedule and name encoding.
fn half_md4_hash(name: &[u8], seed: &[u32; 4], signed: bool) -> u32 {
    let mut state = if *seed == [0; 4] {
        [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
    } else {
        *seed
    };
    let rounds = [
        ([0, 1, 2, 3, 4, 5, 6, 7], [3, 7, 11, 19], 0),
        ([1, 3, 5, 7, 0, 2, 4, 6], [3, 5, 9, 13], 0x5a827999),
        ([3, 7, 2, 6, 1, 5, 0, 4], [3, 9, 11, 15], 0x6ed9eba1),
    ];
    let mut remaining = name;
    while !remaining.is_empty() {
        let pad = (remaining.len() as u32).wrapping_mul(0x01010101);
        let len = remaining.len().min(32);
        let mut words = [pad; 8];
        for (word, bytes) in words.iter_mut().zip(remaining[..len].chunks(4)) {
            for &byte in bytes {
                let byte = if signed {
                    byte as i8 as i32 as u32
                } else {
                    u32::from(byte)
                };
                *word = (*word << 8).wrapping_add(byte);
            }
        }
        let mut work = state;
        for (round, (order, shifts, constant)) in rounds.iter().enumerate() {
            for (step, &word) in order.iter().enumerate() {
                let i = (4 - step % 4) % 4;
                let [b, c, d] = [work[(i + 1) % 4], work[(i + 2) % 4], work[(i + 3) % 4]];
                let mix = match round {
                    0 => (b & c) | (!b & d),
                    1 => (b & c) | (b & d) | (c & d),
                    _ => b ^ c ^ d,
                };
                work[i] = work[i]
                    .wrapping_add(mix)
                    .wrapping_add(words[word])
                    .wrapping_add(*constant)
                    .rotate_left(shifts[step % 4]);
            }
        }
        for (value, delta) in state.iter_mut().zip(work) {
            *value = value.wrapping_add(delta);
        }
        remaining = &remaining[len..];
    }
    let hash = state[1] & !1;
    if hash == 0xffff_fffe {
        0xffff_fffc
    } else {
        hash
    }
}

fn tea_hash(name: &[u8], seed: &[u32; 4]) -> u32 {
    let mut hash = seed[0];
    let mut buf = [0u32; 4];

    for chunk in name.chunks(16) {
        for (i, bytes) in chunk.chunks(4).enumerate() {
            if i >= 4 {
                break;
            }
            let mut val = 0u32;
            for &b in bytes {
                val = (val << 8) | b as u32;
            }
            buf[i] = val;
        }

        for _ in 0..4 {
            hash = hash.wrapping_add(buf[0] ^ buf[1]);
        }
    }
    hash
}
