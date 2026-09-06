// Copyright (c) 2026, https://blog.03k.org. All rights reserved.
use crate::charset;

pub fn decode(value: &[u8]) -> String {
    if !value.windows(2).any(|w| w == b"=?") {

        return charset::sniff(value);
    }

    let bytes = value;
    let mut out = String::with_capacity(value.len());

    let mut pending_gap: Option<String> = None;
    let mut last_was_word = false;
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'=' && bytes.get(i + 1) == Some(&b'?') {
            if let Some((text, consumed)) = parse_word(&bytes[i..]) {

                if let Some(gap) = pending_gap.take() {
                    if !last_was_word {
                        out.push_str(&gap);
                    }
                }
                out.push_str(&text);
                last_was_word = true;
                i += consumed;
                continue;
            }
        }

        let chunk_start = i;
        i += 1;
        while i < bytes.len() && !(bytes[i] == b'=' && bytes.get(i + 1) == Some(&b'?')) {
            i += 1;
        }
        let chunk = charset::sniff(&bytes[chunk_start..i]);
        if chunk.trim().is_empty() && i < bytes.len() {

            pending_gap = Some(match pending_gap.take() {
                Some(prev) => prev + &chunk,
                None => chunk,
            });
        } else {
            if let Some(gap) = pending_gap.take() {
                out.push_str(&gap);
            }
            out.push_str(&chunk);
            last_was_word = false;
        }
    }
    if let Some(gap) = pending_gap {

        if !last_was_word {
            out.push_str(&gap);
        }
    }
    out
}

fn parse_word(b: &[u8]) -> Option<(String, usize)> {
    debug_assert!(b.starts_with(b"=?"));
    let rest = &b[2..];
    let cs_end = rest.iter().position(|&c| c == b'?')?;
    let charset_raw = std::str::from_utf8(&rest[..cs_end]).ok()?;

    let charset_name = charset_raw.split('*').next().unwrap_or(charset_raw);

    let after_cs = &rest[cs_end + 1..];
    let enc = *after_cs.first()?;
    if after_cs.get(1) != Some(&b'?') {
        return None;
    }
    let payload = &after_cs[2..];
    let end = payload.windows(2).position(|w| w == b"?=")?;
    let data = &payload[..end];

    let raw = match enc {
        b'B' | b'b' => b64_lenient(data)?,
        b'Q' | b'q' => crate::qp::decode(data, true),
        _ => return None,
    };

    let consumed = 2 + cs_end + 1 + 1 + 1 + end + 2;
    Some((charset::decode(&raw, Some(charset_name)), consumed))
}

fn b64_lenient(data: &[u8]) -> Option<Vec<u8>> {
    use base64::Engine;
    let cleaned: Vec<u8> = data
        .iter()
        .copied()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    let engine = base64::engine::general_purpose::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::general_purpose::GeneralPurposeConfig::new()
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent)
            .with_decode_allow_trailing_bits(true),
    );
    engine.decode(&cleaned).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_ascii_passes_through() {
        assert_eq!(
            decode(b"Disk failure on /dev/sda"),
            "Disk failure on /dev/sda"
        );
    }

    #[test]
    fn decodes_base64_utf8_word() {
        assert_eq!(decode(b"=?UTF-8?B?5rip5bqm5ZGK6K2m?="), "温度告警");
    }

    #[test]
    fn decodes_base64_gbk_word() {

        assert_eq!(decode(b"=?GB2312?B?zsK2yLjmvq8=?="), "温度告警");
    }

    #[test]
    fn decodes_quoted_printable_word() {
        assert_eq!(decode(b"=?UTF-8?Q?=E6=B8=A9=E5=BA=A6?="), "温度");
        assert_eq!(
            decode(b"=?UTF-8?Q?hello_world?="),
            "hello world",
            "underscore means space inside an encoded word"
        );
    }

    #[test]
    fn whitespace_between_adjacent_words_is_dropped() {

        assert_eq!(
            decode(b"=?UTF-8?B?5rip5bqm?= =?UTF-8?B?5ZGK6K2m?="),
            "温度告警"
        );
    }

    #[test]
    fn whitespace_around_plain_text_is_kept() {
        assert_eq!(decode(b"[ALERT] =?UTF-8?B?5rip5bqm?="), "[ALERT] 温度");
        assert_eq!(decode(b"=?UTF-8?B?5rip5bqm?= now"), "温度 now");
    }

    #[test]
    fn tolerates_missing_base64_padding() {

        assert_eq!(decode(b"=?UTF-8?B?aGVsbG8?="), "hello");
    }

    #[test]
    fn a_malformed_word_is_left_as_text() {

        assert_eq!(decode(b"=?UTF-8?X?whatever?="), "=?UTF-8?X?whatever?=");
        assert_eq!(decode(b"=?truncated"), "=?truncated");
    }

    #[test]
    fn bare_gbk_header_without_encoded_word() {

        assert_eq!(decode(&[0xCE, 0xC2, 0xB6, 0xC8]), "温度");
    }

    #[test]
    fn rfc2231_language_tag_is_ignored() {
        assert_eq!(decode(b"=?UTF-8*zh-CN?B?5rip5bqm?="), "温度");
    }

    #[test]
    fn mixed_words_and_text() {
        assert_eq!(
            decode(b"Re: =?UTF-8?B?5rip5bqm?= (urgent)"),
            "Re: 温度 (urgent)"
        );
    }
}
