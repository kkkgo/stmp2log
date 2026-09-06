// Copyright (c) 2026, https://blog.03k.org. All rights reserved.
use std::io::IsTerminal;
use std::sync::atomic::{AtomicBool, Ordering};

static COLOR: AtomicBool = AtomicBool::new(false);
static DEBUG: AtomicBool = AtomicBool::new(false);

pub fn init(debug: bool) {
    COLOR.store(std::io::stderr().is_terminal(), Ordering::Relaxed);
    DEBUG.store(debug, Ordering::Relaxed);
}

pub fn info(msg: &str) {
    eprintln!("{} {msg}", stamp());
}

pub fn warn(msg: &str) {
    let tag = if COLOR.load(Ordering::Relaxed) {
        "\x1b[33m[WARN]\x1b[0m"
    } else {
        "[WARN]"
    };
    eprintln!("{} {tag} {msg}", stamp());
}

pub fn error(msg: &str) {
    let tag = if COLOR.load(Ordering::Relaxed) {
        "\x1b[31m[ERROR]\x1b[0m"
    } else {
        "[ERROR]"
    };
    eprintln!("{} {tag} {msg}", stamp());
}

pub fn debug(msg: &str) {
    if DEBUG.load(Ordering::Relaxed) {
        eprintln!("{} [debug] {msg}", stamp());
    }
}

fn stamp() -> String {
    fmt_local(now_ms())
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub fn fmt_local(ms: i64) -> String {
    fmt_parts(local_parts(ms))
}

#[cfg(test)]
pub fn fmt_utc(ms: i64) -> String {
    fmt_parts(utc_parts(ms))
}

fn fmt_parts((y, mo, d, h, mi, s): (i64, i64, i64, i64, i64, i64)) -> String {
    format!("{y:04}/{mo:02}/{d:02} {h:02}:{mi:02}:{s:02}")
}

fn utc_parts(ms: i64) -> (i64, i64, i64, i64, i64, i64) {
    let secs = ms.div_euclid(1000);
    let (days, rem) = (secs.div_euclid(86400), secs.rem_euclid(86400));
    let (y, mo, d) = civil_from_days(days);
    (y, mo, d, rem / 3600, (rem % 3600) / 60, rem % 60)
}

fn local_parts(ms: i64) -> (i64, i64, i64, i64, i64, i64) {
    let secs = ms.div_euclid(1000);

    #[cfg(unix)]
    {
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };

        let ok = unsafe { !sys_localtime_r(secs, &mut tm).is_null() };
        if ok {
            return (
                tm.tm_year as i64 + 1900,
                tm.tm_mon as i64 + 1,
                tm.tm_mday as i64,
                tm.tm_hour as i64,
                tm.tm_min as i64,
                tm.tm_sec as i64,
            );
        }
    }

    utc_parts((secs + 8 * 3600) * 1000)
}

#[cfg(all(unix, target_env = "musl"))]
unsafe fn sys_localtime_r(secs: i64, tm: *mut libc::tm) -> *mut libc::tm {
    unsafe extern "C" {
        fn localtime_r(t: *const i64, tm: *mut libc::tm) -> *mut libc::tm;
    }
    unsafe { localtime_r(&secs, tm) }
}

#[cfg(all(unix, not(target_env = "musl")))]
#[allow(deprecated)]
unsafe fn sys_localtime_r(secs: i64, tm: *mut libc::tm) -> *mut libc::tm {
    let t = secs as libc::time_t;
    unsafe { libc::localtime_r(&t, tm) }
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_a_known_instant() {
        assert_eq!(fmt_utc(1_788_353_161_000), "2026/09/02 12:46:01");
    }

    #[test]
    fn the_epoch_and_a_leap_day_come_out_right() {
        assert_eq!(fmt_utc(0), "1970/01/01 00:00:00");
        assert_eq!(fmt_utc(1_709_164_800_000), "2024/02/29 00:00:00");
    }

    #[test]
    fn local_time_is_a_whole_number_of_minutes_away_from_utc() {
        let ms = 1_788_353_161_000;
        let (y, mo, d, h, mi, s) = local_parts(ms);
        assert_eq!(s, 1, "seconds never change across time zones");
        assert!((0..24).contains(&h) && (0..60).contains(&mi));
        assert_eq!(y, 2026);
        assert!(mo == 9 && (1..=3).contains(&d), "got {y}-{mo}-{d}");
    }

    #[test]
    fn civil_from_days_is_the_inverse_of_the_mail_side_conversion() {
        for (y, m, d) in [
            (1970, 1, 1),
            (1999, 12, 31),
            (2000, 3, 1),
            (2024, 2, 29),
            (2026, 9, 2),
            (2100, 1, 1),
        ] {
            let days = days_from_civil(y, m, d);
            assert_eq!(civil_from_days(days), (y, m, d), "{y}-{m}-{d}");
        }
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

    #[test]
    fn debug_output_is_off_unless_asked_for() {
        init(false);
        assert!(!DEBUG.load(Ordering::Relaxed));
        init(true);
        assert!(DEBUG.load(Ordering::Relaxed));
        init(false);
    }
}
