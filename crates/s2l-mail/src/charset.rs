// Copyright (c) 2026, https://blog.03k.org. All rights reserved.
use encoding_rs::Encoding;

pub fn lookup(label: &str) -> Option<&'static Encoding> {
    let t = label.trim().trim_matches(['"', '\'']);
    if t.is_empty() {
        return None;
    }
    if let Some(enc) = Encoding::for_label(t.as_bytes()) {
        return Some(enc);
    }

    let lower = t.to_ascii_lowercase();
    let fallback = match lower.as_str() {
        "gb2312-80" | "gb_2312-80" | "cp936" | "ms936" | "iso-2022-cn" | "iso-2022-cn-ext" => {
            encoding_rs::GBK
        }
        "cp950" | "ms950" => encoding_rs::BIG5,
        "cp932" | "ms932" => encoding_rs::SHIFT_JIS,
        "ansi" | "unknown-8bit" | "x-unknown" | "default" => return None,
        _ => return None,
    };
    Some(fallback)
}

pub fn decode(bytes: &[u8], label: Option<&str>) -> String {
    match label.and_then(lookup) {
        Some(enc) => enc.decode(bytes).0.into_owned(),

        None => sniff(bytes),
    }
}

pub fn sniff(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        Err(_) => {
            if bytes.iter().any(|&b| b >= 0x80) {
                encoding_rs::GBK.decode(bytes).0.into_owned()
            } else {
                String::from_utf8_lossy(bytes).into_owned()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GBK_ALERT: &[u8] = &[0xCE, 0xC2, 0xB6, 0xC8, 0xB8, 0xE6, 0xBE, 0xAF];

    #[test]
    fn resolves_the_labels_devices_actually_send() {
        for label in ["GB2312", "gbk", "GB18030", "gb2312-80", "CP936", " GBK "] {
            assert!(
                lookup(label).is_some(),
                "{label} is a charset real devices send; failing to map it means garbled subjects"
            );
        }
        assert_eq!(lookup("utf-8"), Some(encoding_rs::UTF_8));
        assert_eq!(lookup("Big5"), Some(encoding_rs::BIG5));
        assert!(lookup("").is_none());
        assert!(lookup("no-such-charset").is_none());
    }

    #[test]
    fn quoted_labels_are_unwrapped() {

        assert_eq!(lookup("\"GBK\""), Some(encoding_rs::GBK));
    }

    #[test]
    fn decodes_gbk_to_readable_chinese() {
        assert_eq!(decode(GBK_ALERT, Some("GB2312")), "温度告警");
    }

    #[test]
    fn sniff_prefers_utf8_when_valid() {
        assert_eq!(sniff("温度告警".as_bytes()), "温度告警");
    }

    #[test]
    fn sniff_falls_back_to_gbk_for_high_bytes() {

        assert_eq!(sniff(GBK_ALERT), "温度告警");
    }

    #[test]
    fn sniff_leaves_ascii_alone() {
        assert_eq!(sniff(b"CPU overheat"), "CPU overheat");
    }

    #[test]
    fn bad_bytes_degrade_instead_of_failing() {

        let s = decode(b"ok\xffok", Some("utf-8"));
        assert!(s.contains("ok"), "the readable part must survive: {s:?}");
    }
}
