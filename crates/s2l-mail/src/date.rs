// Copyright (c) 2026, https://blog.03k.org. All rights reserved.
pub fn parse(raw: &[u8]) -> Option<i64> {
    let s = String::from_utf8_lossy(raw);

    let s = match s.find('(') {
        Some(i) => s[..i].to_string(),
        None => s.to_string(),
    };
    let mut it = s.split_whitespace();
    let mut tok = it.next()?;

    if tok.ends_with(',')
        || matches!(
            tok.trim_end_matches(','),
            "Mon" | "Tue" | "Wed" | "Thu" | "Fri" | "Sat" | "Sun"
        )
    {
        tok = it.next()?;
    }

    let day: i64 = tok.parse().ok()?;
    let month = month_num(it.next()?)?;
    let year_raw: i64 = it.next()?.parse().ok()?;

    let year = match year_raw {
        0..=49 => 2000 + year_raw,
        50..=99 => 1900 + year_raw,
        y => y,
    };

    let time = it.next()?;
    let mut tp = time.split(':');
    let hour: i64 = tp.next()?.parse().ok()?;
    let min: i64 = tp.next()?.parse().ok()?;
    let sec: i64 = tp.next().and_then(|v| v.parse().ok()).unwrap_or(0);

    let offset = it.next().and_then(zone_offset).unwrap_or(0);

    if !(1..=31).contains(&day) || hour > 24 || min > 59 || sec > 60 {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86400 + hour * 3600 + min * 60 + sec - offset)
}

fn month_num(m: &str) -> Option<i64> {
    const NAMES: [&str; 12] = [
        "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
    ];
    let l = m.to_ascii_lowercase();
    NAMES
        .iter()
        .position(|n| l.starts_with(n))
        .map(|i| i as i64 + 1)
}

fn zone_offset(z: &str) -> Option<i64> {
    let z = z.trim();
    if let Some(rest) = z.strip_prefix(['+', '-']) {
        if rest.len() >= 4 {
            let h: i64 = rest.get(..2)?.parse().ok()?;
            let m: i64 = rest.get(2..4)?.parse().ok()?;
            let mag = h * 3600 + m * 60;
            return Some(if z.starts_with('-') { -mag } else { mag });
        }
        return None;
    }

    Some(match z.to_ascii_uppercase().as_str() {
        "UT" | "UTC" | "GMT" | "Z" => 0,
        "EST" => -5 * 3600,
        "EDT" => -4 * 3600,
        "CST" => -6 * 3600,
        "CDT" => -5 * 3600,
        "MST" => -7 * 3600,
        "MDT" => -6 * 3600,
        "PST" => -8 * 3600,
        "PDT" => -7 * 3600,
        _ => return None,
    })
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_normal_date() {
        assert_eq!(parse(b"Tue, 2 Sep 2026 20:46:01 +0800"), Some(1788353161));
    }

    #[test]
    fn weekday_is_optional() {
        assert_eq!(
            parse(b"2 Sep 2026 20:46:01 +0800"),
            parse(b"Tue, 2 Sep 2026 20:46:01 +0800")
        );
    }

    #[test]
    fn seconds_are_optional() {
        assert_eq!(parse(b"Tue, 2 Sep 2026 20:46 +0800"), Some(1788353160));
    }

    #[test]
    fn handles_utc_and_named_zones() {
        assert_eq!(parse(b"2 Sep 2026 12:46:01 GMT"), Some(1788353161));
        assert_eq!(parse(b"2 Sep 2026 12:46:01 +0000"), Some(1788353161));
        assert_eq!(parse(b"2 Sep 2026 07:46:01 EST"), Some(1788353161));
    }

    #[test]
    fn negative_offsets_go_the_right_way() {
        let utc = parse(b"2 Sep 2026 12:00:00 +0000").unwrap();
        assert_eq!(parse(b"2 Sep 2026 20:00:00 +0800").unwrap(), utc);
        assert_eq!(parse(b"2 Sep 2026 04:00:00 -0800").unwrap(), utc);
    }

    #[test]
    fn strips_paren_comments() {
        assert_eq!(
            parse(b"Tue, 2 Sep 2026 20:46:01 +0800 (CST)"),
            Some(1788353161)
        );
    }

    #[test]
    fn two_digit_years() {
        assert_eq!(parse(b"1 Jan 70 00:00:00 +0000"), Some(0));
        assert_eq!(
            parse(b"1 Jan 26 00:00:00 +0000"),
            parse(b"1 Jan 2026 00:00:00 +0000")
        );
    }

    #[test]
    fn epoch_and_leap_day() {
        assert_eq!(parse(b"1 Jan 1970 00:00:00 +0000"), Some(0));
        assert_eq!(parse(b"29 Feb 2024 00:00:00 +0000"), Some(1709164800));
    }

    #[test]
    fn garbage_returns_none_rather_than_a_wrong_time() {
        assert_eq!(parse(b""), None);
        assert_eq!(parse(b"not a date at all"), None);
        assert_eq!(parse(b"32 Sep 2026 20:46:01 +0800"), None);
        assert_eq!(parse(b"2 Xxx 2026 20:46:01 +0800"), None);
    }

    #[test]
    fn missing_zone_is_treated_as_utc() {
        assert_eq!(parse(b"2 Sep 2026 12:46:01"), Some(1788353161));
    }
}
