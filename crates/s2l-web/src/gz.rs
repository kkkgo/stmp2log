// Copyright (c) 2026, https://blog.03k.org. All rights reserved.
const HEADER: [u8; 10] = [0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff];

pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

pub fn wrap(deflate: &[u8], plain_crc: u32, plain_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(deflate.len() + 18);
    out.extend_from_slice(&HEADER);
    out.extend_from_slice(deflate);
    out.extend_from_slice(&plain_crc.to_le_bytes());
    out.extend_from_slice(&(plain_len as u32).to_le_bytes());
    out
}

pub fn compress(plain: &[u8]) -> Vec<u8> {
    let deflate = miniz_oxide::deflate::compress_to_vec(plain, 9);
    wrap(&deflate, crc32(plain), plain.len())
}

pub fn decompress(gz: &[u8]) -> Option<Vec<u8>> {
    if gz.len() < 18 || gz[0] != 0x1f || gz[1] != 0x8b || gz[2] != 0x08 {
        return None;
    }
    let flg = gz[3];
    let mut p = 10usize;
    if flg & 0x04 != 0 {
        let xlen = u16::from_le_bytes([*gz.get(p)?, *gz.get(p + 1)?]) as usize;
        p += 2 + xlen;
    }
    for bit in [0x08u8, 0x10] {
        if flg & bit != 0 {
            p += gz.get(p..)?.iter().position(|&b| b == 0)? + 1;
        }
    }
    if flg & 0x02 != 0 {
        p += 2;
    }
    if p + 8 > gz.len() {
        return None;
    }
    let body = &gz[p..gz.len() - 8];
    let tail = &gz[gz.len() - 8..];
    let expect = u32::from_le_bytes([tail[0], tail[1], tail[2], tail[3]]);

    let plain = miniz_oxide::inflate::decompress_to_vec(body).ok()?;
    (crc32(&plain) == expect).then_some(plain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_matches_known_vectors() {
        assert_eq!(crc32(b""), 0x0000_0000);
        assert_eq!(crc32(b"a"), 0xe8b7_be43);
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(
            crc32(b"The quick brown fox jumps over the lazy dog"),
            0x414f_a339
        );
    }

    #[test]
    fn round_trips() {
        for case in [
            b"".to_vec(),
            b"hello".to_vec(),
            vec![0u8; 100_000],
            (0..=255u8).cycle().take(70_000).collect::<Vec<_>>(),
            "温度告警".repeat(500).into_bytes(),
        ] {
            let gz = compress(&case);
            assert_eq!(&gz[..2], &[0x1f, 0x8b], "gzip magic");
            assert_eq!(decompress(&gz).unwrap(), case);
        }
    }

    #[test]
    fn wrap_matches_compress() {
        let plain = b"stmp2log stmp2log stmp2log";
        let deflate = miniz_oxide::deflate::compress_to_vec(plain, 9);
        assert_eq!(wrap(&deflate, crc32(plain), plain.len()), compress(plain));
    }

    #[test]
    fn rejects_garbage_instead_of_panicking() {
        assert!(decompress(b"not gzip at all!!!!!").is_none());
        assert!(decompress(b"short").is_none());
        let mut gz = compress(b"payload");
        let n = gz.len();
        gz[n - 5] ^= 0xff;
        assert!(decompress(&gz).is_none());
    }

    #[test]
    fn output_is_deterministic() {
        assert_eq!(compress(b"same input"), compress(b"same input"));
    }
}
