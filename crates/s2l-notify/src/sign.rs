// Copyright (c) 2026, https://blog.03k.org. All rights reserved.
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::Sha256;

fn b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub fn dingtalk(timestamp_ms: i64, secret: &str) -> String {
    let mut mac =
        <Hmac<Sha256>>::new_from_slice(secret.as_bytes()).expect("HMAC accepts keys of any length");
    mac.update(format!("{timestamp_ms}\n{secret}").as_bytes());
    b64(&mac.finalize().into_bytes())
}

pub fn feishu(timestamp_s: i64, secret: &str) -> String {
    let key = format!("{timestamp_s}\n{secret}");
    let mut mac =
        <Hmac<Sha256>>::new_from_slice(key.as_bytes()).expect("HMAC accepts keys of any length");
    mac.update(b"");
    b64(&mac.finalize().into_bytes())
}

pub fn aliyun(params: &[(String, String)], access_key_secret: &str) -> String {
    let mut sorted: Vec<&(String, String)> = params.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));

    let canonical = sorted
        .iter()
        .map(|(k, v)| format!("{}={}", rfc3986(k), rfc3986(v)))
        .collect::<Vec<_>>()
        .join("&");
    let string_to_sign = format!("POST&{}&{}", rfc3986("/"), rfc3986(&canonical));

    let key = format!("{access_key_secret}&");
    let mut mac =
        <Hmac<Sha1>>::new_from_slice(key.as_bytes()).expect("HMAC accepts keys of any length");
    mac.update(string_to_sign.as_bytes());
    b64(&mac.finalize().into_bytes())
}

pub fn rfc3986(s: &str) -> String {
    const UNRESERVED: &[u8] = b"-_.~";
    let mut out = String::with_capacity(s.len() * 3 / 2);
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || UNRESERVED.contains(&b) {
            out.push(b as char);
        } else {
            out.push('%');
            out.push_str(&format!("{b:02X}"));
        }
    }
    out
}

pub fn urlencode(s: &str) -> String {
    rfc3986(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dingtalk_matches_the_reference_vector() {
        assert_eq!(
            dingtalk(1_788_353_161_000, "SECabc123"),
            "5OaY8IqHiwWhu51heCgdSRr+arSGrymRnTobQyLkoO4="
        );
    }

    #[test]
    fn feishu_matches_the_reference_vector() {
        assert_eq!(
            feishu(1_788_353_161, "FSsecret456"),
            "9cm362w5O7lGHftF1F9tcWzWRMLrsLb1mfwjKp47Mlc="
        );
    }

    #[test]
    fn dingtalk_and_feishu_do_not_produce_the_same_thing() {
        let (ts, secret) = (1_788_353_161, "same-secret");
        assert_ne!(
            dingtalk(ts, secret),
            feishu(ts, secret),
            "the two schemes must not be interchangeable, or a copy-paste bug goes unnoticed"
        );
    }

    #[test]
    fn aliyun_matches_the_reference_vector() {
        let params: Vec<(String, String)> = [
            ("Action", "SendSms"),
            ("Format", "JSON"),
            ("PhoneNumbers", "13800138000"),
            ("SignName", "test"),
            ("Timestamp", "2026-09-02T12:46:01Z"),
            ("Version", "2017-05-25"),
            ("AccessKeyId", "LTAItest"),
            ("SignatureMethod", "HMAC-SHA1"),
            ("SignatureNonce", "0.123"),
            ("SignatureVersion", "1.0"),
            ("TemplateCode", "SMS_1"),
            ("TemplateParam", r#"{"name":"x"}"#),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

        assert_eq!(
            aliyun(&params, "SECRETtest"),
            "l8OEeOKCXHZzC9F4W1YLZXURb4A="
        );
    }

    #[test]
    fn aliyun_signature_is_order_independent_because_it_sorts() {
        let a: Vec<(String, String)> = [("B", "2"), ("A", "1")]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let b: Vec<(String, String)> = [("A", "1"), ("B", "2")]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        assert_eq!(aliyun(&a, "s"), aliyun(&b, "s"));
    }

    #[test]
    fn rfc3986_encodes_the_characters_that_break_aliyun() {
        assert_eq!(rfc3986(" "), "%20");
        assert_eq!(rfc3986("!"), "%21");
        assert_eq!(rfc3986("*"), "%2A");
        assert_eq!(rfc3986("'"), "%27");
        assert_eq!(rfc3986("("), "%28");
        assert_eq!(rfc3986(")"), "%29");
        assert_eq!(rfc3986("/"), "%2F");
        assert_eq!(rfc3986(":"), "%3A");
        assert_eq!(
            rfc3986("-_.~"),
            "-_.~",
            "unreserved characters stay literal"
        );
        assert_eq!(rfc3986("abcXYZ019"), "abcXYZ019");
    }

    #[test]
    fn rfc3986_encodes_multibyte_as_utf8_bytes() {
        assert_eq!(rfc3986("温"), "%E6%B8%A9");
    }

    #[test]
    fn dingtalk_sign_is_url_encoded_before_going_into_the_query_string() {
        let sig = dingtalk(1_788_353_161_000, "SECabc123");
        assert_eq!(
            urlencode(&sig),
            "5OaY8IqHiwWhu51heCgdSRr%2BarSGrymRnTobQyLkoO4%3D"
        );
    }
}
