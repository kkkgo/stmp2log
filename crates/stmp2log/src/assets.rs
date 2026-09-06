// Copyright (c) 2026, https://blog.03k.org. All rights reserved.
use std::sync::Arc;

use s2l_web::StaticAsset;

static EMBEDDED: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/index.html.deflate"));

pub const BASE_PLACEHOLDER: &str = "__S2L_BASE__";

pub fn prepare(base: &str) -> Result<Arc<StaticAsset>, String> {
    let plain = miniz_oxide::inflate::decompress_to_vec(EMBEDDED).map_err(|e| {
        format!("could not decompress the embedded frontend (corrupt build artefact?): {e:?}")
    })?;
    Ok(Arc::new(StaticAsset::new(&plain, BASE_PLACEHOLDER, base)))
}

pub fn is_placeholder() -> bool {
    miniz_oxide::inflate::decompress_to_vec(EMBEDDED)
        .map(|b| String::from_utf8_lossy(&b).contains("has not been built"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_embedded_blob_inflates() {
        let a = prepare("/stmp2log").expect("the embedded frontend does not decompress");
        assert!(!a.plain.is_empty());
        assert_eq!(&a.gzip[..2], &[0x1f, 0x8b], "gzip magic");
    }

    #[test]
    fn the_placeholder_check_agrees_with_what_is_embedded() {
        let a = prepare("").unwrap();
        let html = String::from_utf8_lossy(&a.plain).to_string();
        assert_eq!(is_placeholder(), html.contains("has not been built"));
    }
}
