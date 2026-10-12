//! Minimal redistributable fixture construction, with no third-party OS content.
pub fn iso(payload: &[u8]) -> Vec<u8> {
    let sectors = 21 + payload.len().div_ceil(2048);
    let mut bytes = vec![0; sectors * 2048];
    let pvd = &mut bytes[16 * 2048..17 * 2048];
    pvd[0] = 1;
    pvd[1..6].copy_from_slice(b"CD001");
    pvd[6] = 1;
    pvd[80..84].copy_from_slice(&(sectors as u32).to_le_bytes());
    pvd[84..88].copy_from_slice(&(sectors as u32).to_be_bytes());
    pvd[128..132].copy_from_slice(&[0, 8, 8, 0]);
    pvd[156..190].copy_from_slice(&record(20, 2048, 2, &[0]));
    bytes[17 * 2048] = 255;
    bytes[17 * 2048 + 1..17 * 2048 + 6].copy_from_slice(b"CD001");
    bytes[17 * 2048 + 6] = 1;
    let mut pos = 20 * 2048;
    for rec in [
        record(20, 2048, 2, &[0]),
        record(20, 2048, 2, &[1]),
        record(21, payload.len() as u32, 0, b"ANSWER.EXE;1"),
    ] {
        bytes[pos..pos + rec.len()].copy_from_slice(&rec);
        pos += rec.len();
    }
    bytes[21 * 2048..21 * 2048 + payload.len()].copy_from_slice(payload);
    bytes
}

fn record(extent: u32, size: u32, flags: u8, name: &[u8]) -> Vec<u8> {
    let len = 33 + name.len() + usize::from(name.len() % 2 == 0);
    let mut r = vec![0; len];
    r[0] = len as u8;
    r[2..6].copy_from_slice(&extent.to_le_bytes());
    r[6..10].copy_from_slice(&extent.to_be_bytes());
    r[10..14].copy_from_slice(&size.to_le_bytes());
    r[14..18].copy_from_slice(&size.to_be_bytes());
    r[25] = flags;
    r[28..32].copy_from_slice(&[1, 0, 0, 1]);
    r[32] = name.len() as u8;
    r[33..33 + name.len()].copy_from_slice(name);
    r
}

/// A valid minimal AMD64 PE image with a single function: mov eax,42; ret.
pub fn pe() -> Vec<u8> {
    let mut b = vec![0; 1024];
    b[..2].copy_from_slice(b"MZ");
    b[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
    b[0x80..0x84].copy_from_slice(b"PE\0\0");
    b[0x84..0x86].copy_from_slice(&0x8664_u16.to_le_bytes());
    b[0x86..0x88].copy_from_slice(&1_u16.to_le_bytes());
    b[0x94..0x96].copy_from_slice(&240_u16.to_le_bytes());
    b[0x96..0x98].copy_from_slice(&0x22_u16.to_le_bytes());
    let o = 0x98;
    b[o..o + 2].copy_from_slice(&0x20b_u16.to_le_bytes());
    b[o + 16..o + 20].copy_from_slice(&0x1000_u32.to_le_bytes());
    b[o + 24..o + 32].copy_from_slice(&0x140000000_u64.to_le_bytes());
    b[o + 32..o + 36].copy_from_slice(&4096_u32.to_le_bytes());
    b[o + 36..o + 40].copy_from_slice(&512_u32.to_le_bytes());
    b[o + 56..o + 60].copy_from_slice(&8192_u32.to_le_bytes());
    b[o + 60..o + 64].copy_from_slice(&512_u32.to_le_bytes());
    b[o + 68..o + 70].copy_from_slice(&3_u16.to_le_bytes());
    b[o + 108..o + 112].copy_from_slice(&16_u32.to_le_bytes());
    let s = o + 240;
    b[s..s + 5].copy_from_slice(b".text");
    b[s + 8..s + 12].copy_from_slice(&6_u32.to_le_bytes());
    b[s + 12..s + 16].copy_from_slice(&4096_u32.to_le_bytes());
    b[s + 16..s + 20].copy_from_slice(&512_u32.to_le_bytes());
    b[s + 20..s + 24].copy_from_slice(&512_u32.to_le_bytes());
    b[s + 36..s + 40].copy_from_slice(&0x60000020_u32.to_le_bytes());
    b[512..518].copy_from_slice(&[0xb8, 42, 0, 0, 0, 0xc3]);
    b
}
