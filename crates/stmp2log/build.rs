// Copyright (c) 2026, https://blog.03k.org. All rights reserved.
use std::path::{Path, PathBuf};

const PLACEHOLDER: &str = r#"<!doctype html>
<meta charset="utf-8">
<title>stmp2log &mdash; frontend not built</title>
<style>
  :root{color-scheme:dark}
  body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0e1320;
       color:#e6ecf7;font:16px/1.7 ui-sans-serif,system-ui,"Segoe UI",sans-serif}
  main{max-width:34rem;padding:2rem}
  h1{font-size:1.3rem;margin:0 0 .75rem}
  code{background:#1b2334;padding:.15em .45em;border-radius:6px;font-size:.92em}
  p{color:#9fb0c9}
</style>
<main>
  <h1>The stmp2log backend is running, but the web UI has not been built</h1>
  <p>This is the built-in placeholder page. Build the frontend, then recompile:</p>
  <p><code>bash webui/build.sh &amp;&amp; cargo build</code></p>
  <p>Or just run <code>bash build.sh</code> in the repo root, which does both steps.</p>
</main>
"#;

fn main() {
    let src = Path::new("assets/index.html");
    println!("cargo:rerun-if-changed=assets/index.html");

    let html = std::fs::read(src).unwrap_or_else(|_| PLACEHOLDER.as_bytes().to_vec());
    let deflated = miniz_oxide::deflate::compress_to_vec(&html, 9);

    let out = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR")).join("index.html.deflate");
    std::fs::write(&out, &deflated).expect("could not write the embedded frontend");
}
