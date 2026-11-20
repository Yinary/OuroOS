//! QEMU /chosen/rng-seed 提供启动熵。每次请求使用不同的 ChaCha20 块；
//! 不使用时钟或可预测的回退种子。块函数按 RFC 8439 §2.3 实现。
use spin::Mutex;

static STREAM: Mutex<Option<([u32; 8], u32)>> = Mutex::new(None);

pub(crate) fn init() {
    let Ok(dt) = polyhal::mem::get_fdt() else {
        return;
    };
    let Some(node) = dt.find_nodes("/chosen").next() else {
        return;
    };
    let Some(prop) = node.find_property("rng-seed") else {
        return;
    };
    let Some(bytes) = prop.raw_value().get(..32) else {
        return;
    };
    if bytes.iter().all(|b| *b == 0) {
        return;
    }
    let mut key = [0; 8];
    for (w, b) in key.iter_mut().zip(bytes.chunks_exact(4)) {
        *w = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    }
    *STREAM.lock() = Some((key, 0));
}

pub(crate) fn exec_random() -> Option<[u8; 16]> {
    let mut stream = STREAM.lock();
    let (key, counter) = stream.as_mut()?;
    let n = *counter;
    *counter = n.checked_add(1)?;
    let mut x = [0u32; 16];
    x[..4].copy_from_slice(&[0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]);
    x[4..12].copy_from_slice(key);
    x[12] = n;
    let initial = x;
    for _ in 0..10 {
        for i in 0..4 {
            quarter(&mut x, i, 4 + i, 8 + i, 12 + i);
        }
        for i in 0..4 {
            quarter(
                &mut x,
                i,
                4 + (i + 1) % 4,
                8 + (i + 2) % 4,
                12 + (i + 3) % 4,
            );
        }
    }
    let mut bytes = [0; 16];
    for (i, part) in bytes.chunks_exact_mut(4).enumerate() {
        part.copy_from_slice(&x[i].wrapping_add(initial[i]).to_le_bytes());
    }
    Some(bytes)
}

fn quarter(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    for (r, s) in [(16, 12), (8, 7)] {
        x[a] = x[a].wrapping_add(x[b]);
        x[d] = (x[d] ^ x[a]).rotate_left(r);
        x[c] = x[c].wrapping_add(x[d]);
        x[b] = (x[b] ^ x[c]).rotate_left(s);
    }
}
