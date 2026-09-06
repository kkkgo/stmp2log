// Copyright (c) 2026, https://blog.03k.org. All rights reserved.
pub fn decode(input: &[u8], underscore_is_space: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        match input[i] {
            b'_' if underscore_is_space => {
                out.push(b' ');
                i += 1;
            }
            b'=' => {

                if let Some(rest) = input.get(i + 1..) {
                    if rest.starts_with(b"\r\n") {
                        i += 3;
                        continue;
                    }
                    if rest.starts_with(b"\n") {
                        i += 2;
                        continue;
                    }
                }
                match (hexval(input.get(i + 1)), hexval(input.get(i + 2))) {
                    (Some(h), Some(l)) => {
                        out.push(h << 4 | l);
                        i += 3;
                    }

                    _ => {
                        out.push(b'=');
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    out
}

fn hexval(b: Option<&u8>) -> Option<u8> {
    match b? {
        c @ b'0'..=b'9' => Some(c - b'0'),
        c @ b'a'..=b'f' => Some(c - b'a' + 10),
        c @ b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_hex_escapes() {
        assert_eq!(decode(b"a=20b", false), b"a b");
        assert_eq!(decode(b"=E6=B8=A9", false), "温".as_bytes());
    }

    #[test]
    fn accepts_lowercase_hex() {
        assert_eq!(decode(b"=e6=b8=a9", false), "温".as_bytes());
    }

    #[test]
    fn soft_line_breaks_vanish() {
        assert_eq!(decode(b"long=\r\nline", false), b"longline");
        assert_eq!(decode(b"long=\nline", false), b"longline", "bare LF too");
    }

    #[test]
    fn underscore_is_space_only_in_encoded_words() {
        assert_eq!(decode(b"a_b", true), b"a b");
        assert_eq!(decode(b"a_b", false), b"a_b");
    }

    #[test]
    fn a_bare_equals_survives_when_it_cannot_be_an_escape() {

        assert_eq!(decode(b"CPU=high", false), b"CPU=high");
        assert_eq!(decode(b"trailing=", false), b"trailing=");
        assert_eq!(decode(b"a=Zz", false), b"a=Zz", "Z is not a hex digit");
    }

    #[test]
    fn an_unencoded_equals_before_two_hex_digits_is_indistinguishable() {

        assert_eq!(decode(b"CPU=95%", false), b"CPU\x95%");
    }
}
