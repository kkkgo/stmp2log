// Copyright (c) 2026, https://blog.03k.org. All rights reserved.
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::StoreError;

pub const MAX_BODY_BYTES: u64 = 4 * 1024 * 1024;

pub const MAX_RECORDS: usize = 2000;

pub struct Segments {
    dir: PathBuf,

    nums: Vec<u32>,
    cur: Option<Open>,
}

struct Open {
    num: u32,
    meta: BufWriter<File>,
    body: BufWriter<File>,
    body_len: u64,
    records: usize,

    att: Option<BufWriter<File>>,
    att_len: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Loc {
    pub seg: u32,
    pub off: u64,
    pub len: u32,
}

impl Segments {
    pub fn open(dir: &Path) -> Result<Self, StoreError> {
        fs::create_dir_all(dir)?;
        let mut nums = Vec::new();
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Some(stem) = name.strip_suffix(".meta") {
                if let Ok(n) = stem.parse::<u32>() {
                    nums.push(n);
                }
            }
        }
        nums.sort_unstable();
        Ok(Self {
            dir: dir.to_path_buf(),
            nums,
            cur: None,
        })
    }

    pub fn nums(&self) -> &[u32] {
        &self.nums
    }

    pub fn meta_path(&self, n: u32) -> PathBuf {
        self.dir.join(format!("{n:06}.meta"))
    }

    pub fn body_path(&self, n: u32) -> PathBuf {
        self.dir.join(format!("{n:06}.body"))
    }
    pub fn att_path(&self, n: u32) -> PathBuf {
        self.dir.join(format!("{n:06}.att"))
    }

    pub fn read_att(&self, seg: u32, off: u64, len: u32) -> Result<Option<Vec<u8>>, StoreError> {
        let mut f = match File::open(self.att_path(seg)) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        f.seek(SeekFrom::Start(off))?;
        let mut buf = vec![0u8; len as usize];
        if f.read_exact(&mut buf).is_err() {
            return Ok(None);
        }
        Ok(Some(buf))
    }

    pub fn read_meta(&self, n: u32) -> Result<Vec<crate::MetaLine>, StoreError> {
        let path = self.meta_path(n);
        let file = match File::open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut out = Vec::new();
        for line in BufReader::new(file).lines() {
            let Ok(line) = line else { break };
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(rec) = serde_json::from_str::<crate::MetaLine>(&line) {
                out.push(rec);
            }
        }
        Ok(out)
    }

    pub fn read_body_at(&self, loc: Loc) -> Result<Option<crate::BodyRec>, StoreError> {
        let mut f = match File::open(self.body_path(loc.seg)) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        f.seek(SeekFrom::Start(loc.off))?;
        let mut buf = vec![0u8; loc.len as usize];
        if f.read_exact(&mut buf).is_err() {
            return Ok(None);
        }
        Ok(serde_json::from_slice(&buf).ok())
    }

    pub fn stream_body(&self, n: u32, mut f: impl FnMut(crate::BodyRec)) -> Result<(), StoreError> {
        let file = match File::open(self.body_path(n)) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };

        for line in BufReader::with_capacity(64 * 1024, file).lines() {
            let Ok(line) = line else { break };
            if let Ok(rec) = serde_json::from_str::<crate::BodyRec>(&line) {
                f(rec);
            }
        }
        Ok(())
    }

    pub fn append(
        &mut self,
        atts: &[Vec<u8>],
        body: impl FnOnce(&[(u64, u32)]) -> crate::BodyRec,
        meta: impl FnOnce(Loc) -> crate::MetaLine,
    ) -> Result<Loc, StoreError> {
        let att_bytes: u64 = atts.iter().map(|a| a.len() as u64).sum();

        self.ensure_open(att_bytes + 4096)?;

        let mut spots: Vec<(u64, u32)> = Vec::with_capacity(atts.len());
        if !atts.is_empty() {
            let path = self.att_path(self.cur.as_ref().expect("ensure_open just set it").num);
            let seg = self.cur.as_mut().expect("ensure_open just set it");
            if seg.att.is_none() {
                let f = OpenOptions::new().create(true).append(true).open(path)?;
                seg.att_len = f.metadata()?.len();
                seg.att = Some(BufWriter::new(f));
            }
            let w = seg.att.as_mut().expect("just opened");
            for a in atts {
                w.write_all(a)?;
                spots.push((seg.att_len, a.len() as u32));
                seg.att_len += a.len() as u64;
            }
            w.flush()?;
        }

        let body_json = serde_json::to_vec(&body(&spots))?;
        let seg = self.cur.as_mut().expect("ensure_open just set it");
        let loc = Loc {
            seg: seg.num,
            off: seg.body_len,
            len: body_json.len() as u32,
        };
        seg.body.write_all(&body_json)?;
        seg.body.write_all(b"\n")?;
        seg.body_len += body_json.len() as u64 + 1;

        seg.body.flush()?;

        let meta_json = serde_json::to_vec(&meta(loc))?;
        seg.meta.write_all(&meta_json)?;
        seg.meta.write_all(b"\n")?;
        seg.meta.flush()?;
        seg.records += 1;
        Ok(loc)
    }

    pub fn append_meta(&mut self, line: &crate::MetaLine) -> Result<(), StoreError> {
        self.ensure_open(0)?;
        let seg = self.cur.as_mut().expect("ensure_open just set it");
        let json = serde_json::to_vec(line)?;
        seg.meta.write_all(&json)?;
        seg.meta.write_all(b"\n")?;
        seg.meta.flush()?;
        Ok(())
    }

    pub fn drop_segment(&mut self, n: u32) -> Result<(), StoreError> {
        if self.cur.as_ref().is_some_and(|c| c.num == n) {
            return Ok(());
        }
        let _ = fs::remove_file(self.meta_path(n));
        let _ = fs::remove_file(self.body_path(n));
        let _ = fs::remove_file(self.att_path(n));
        self.nums.retain(|&x| x != n);
        Ok(())
    }

    pub fn disk_usage(&self) -> u64 {
        self.nums
            .iter()
            .flat_map(|&n| [self.meta_path(n), self.body_path(n), self.att_path(n)])
            .filter_map(|p| fs::metadata(p).ok())
            .map(|m| m.len())
            .sum()
    }

    fn ensure_open(&mut self, incoming: u64) -> Result<(), StoreError> {
        let need_roll = match &self.cur {
            None => true,
            Some(c) => c.body_len + incoming > MAX_BODY_BYTES || c.records >= MAX_RECORDS,
        };
        if !need_roll {
            return Ok(());
        }

        let num = match self.nums.last() {
            Some(&last) if self.cur.is_none() => last,
            Some(&last) => last + 1,
            None => 1,
        };
        if !self.nums.contains(&num) {
            self.nums.push(num);
            self.nums.sort_unstable();
        }

        let meta = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.meta_path(num))?;
        let body = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.body_path(num))?;
        let body_len = body.metadata()?.len();

        let records = if body_len > 0 { MAX_RECORDS } else { 0 };
        let full = body_len + incoming > MAX_BODY_BYTES;

        self.cur = Some(Open {
            num,
            meta: BufWriter::new(meta),
            body: BufWriter::new(body),
            body_len,
            records: if full { records } else { 0 },
            att: None,
            att_len: 0,
        });

        if full {
            return self.ensure_open(incoming);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BodyRec, MetaLine};

    fn tmp() -> PathBuf {
        let n: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let p = std::env::temp_dir().join(format!("s2l-seg-{n}-{:?}", std::thread::current().id()));
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn body(id: u64, text: &str) -> BodyRec {
        BodyRec {
            id,
            text: text.into(),
            ..Default::default()
        }
    }

    #[test]
    fn append_then_read_back_by_location() {
        let dir = tmp();
        let mut s = Segments::open(&dir).unwrap();
        let loc = s
            .append(
                &[],
                |_| body(1, "hello"),
                |l| MetaLine::Del { id: l.seg as u64 },
            )
            .unwrap();
        assert_eq!(s.read_body_at(loc).unwrap().unwrap().text, "hello");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn locations_stay_valid_across_reopen() {
        let dir = tmp();
        let mut locs = Vec::new();
        {
            let mut s = Segments::open(&dir).unwrap();
            for i in 1..=5 {
                locs.push(
                    s.append(
                        &[],
                        |_| body(i, &format!("body {i}")),
                        |l| MetaLine::Del { id: l.off },
                    )
                    .unwrap(),
                );
            }
        }
        let s = Segments::open(&dir).unwrap();
        for (i, loc) in locs.iter().enumerate() {
            let got = s.read_body_at(*loc).unwrap().unwrap();
            assert_eq!(got.text, format!("body {}", i + 1));
        }
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reopening_continues_the_last_segment_instead_of_starting_a_new_one() {
        let dir = tmp();
        for _ in 0..4 {
            let mut s = Segments::open(&dir).unwrap();
            s.append(&[], |_| body(1, "x"), |l| MetaLine::Del { id: l.off })
                .unwrap();
        }
        let s = Segments::open(&dir).unwrap();
        assert_eq!(
            s.nums(),
            &[1],
            "four restarts must not create four segments"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rolls_to_a_new_segment_when_the_record_count_is_hit() {
        let dir = tmp();
        let mut s = Segments::open(&dir).unwrap();
        for i in 0..(MAX_RECORDS + 5) {
            s.append(
                &[],
                |_| body(i as u64, "x"),
                |l| MetaLine::Del { id: l.off },
            )
            .unwrap();
        }
        assert!(s.nums().len() >= 2, "segments were {:?}", s.nums());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_truncated_last_line_does_not_lose_the_rest() {
        let dir = tmp();
        {
            let mut s = Segments::open(&dir).unwrap();
            for i in 1..=3 {
                s.append_meta(&MetaLine::Del { id: i }).unwrap();
            }
        }
        let path = dir.join("000001.meta");
        let mut content = fs::read_to_string(&path).unwrap();
        content.push_str("{\"t\":\"d\",\"id\":9");
        fs::write(&path, content).unwrap();

        let s = Segments::open(&dir).unwrap();
        let lines = s.read_meta(1).unwrap();
        assert_eq!(lines.len(), 3, "the three complete lines must survive");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn streaming_visits_every_body_record() {
        let dir = tmp();
        let mut s = Segments::open(&dir).unwrap();
        for i in 1..=10 {
            s.append(
                &[],
                |_| body(i, &format!("t{i}")),
                |l| MetaLine::Del { id: l.off },
            )
            .unwrap();
        }
        let mut seen = Vec::new();
        s.stream_body(1, |r| seen.push(r.id)).unwrap();
        assert_eq!(seen, (1..=10).collect::<Vec<_>>());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dropping_a_segment_removes_both_files() {
        let dir = tmp();
        let mut s = Segments::open(&dir).unwrap();
        for i in 0..(MAX_RECORDS + 5) {
            s.append(
                &[],
                |_| body(i as u64, "x"),
                |l| MetaLine::Del { id: l.off },
            )
            .unwrap();
        }
        let first = s.nums()[0];
        s.drop_segment(first).unwrap();
        assert!(!s.meta_path(first).exists());
        assert!(!s.body_path(first).exists());
        assert!(!s.nums().contains(&first));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_segment_being_written_is_never_dropped() {
        let dir = tmp();
        let mut s = Segments::open(&dir).unwrap();
        let loc = s
            .append(&[], |_| body(1, "keep me"), |l| MetaLine::Del { id: l.off })
            .unwrap();
        s.drop_segment(loc.seg).unwrap();
        assert!(s.body_path(loc.seg).exists());
        assert_eq!(s.read_body_at(loc).unwrap().unwrap().text, "keep me");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reading_a_missing_segment_is_not_an_error() {
        let dir = tmp();
        let s = Segments::open(&dir).unwrap();
        assert!(s.read_meta(42).unwrap().is_empty());
        assert!(
            s.read_body_at(Loc {
                seg: 42,
                off: 0,
                len: 10
            })
            .unwrap()
            .is_none()
        );
        fs::remove_dir_all(&dir).ok();
    }
}
