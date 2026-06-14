//! Maps a decoded [`BinaryCookies`] into the golden JSON shape by hand —
//! deliberately independent of the crate's `serde` feature.

use safari_binarycookies::BinaryCookies;
use serde_json::{Value, json};

pub(crate) fn to_golden_value(jar: &BinaryCookies) -> Value {
    let pages: Vec<Value> = jar
        .pages
        .iter()
        .map(|page| {
            let cookies: Vec<Value> = page
                .cookies
                .iter()
                .map(|cookie| {
                    json!({
                        "flags_bits": cookie.flags.bits(),
                        "secure": cookie.is_secure(),
                        "http_only": cookie.is_http_only(),
                        "domain": cookie.domain,
                        "name": cookie.name,
                        "path": cookie.path,
                        "value": cookie.value,
                        // The Go exporter maps both a missing and a zero-length
                        // comment to null (`len(c.Comment) > 0`).
                        "comment": cookie.comment.as_deref().filter(|comment| !comment.is_empty()),
                        "expires_unix": cookie.expires_unix(),
                        "creation_unix": cookie.creation_unix(),
                    })
                })
                .collect();
            json!({
                "cookie_offsets": page.offsets,
                "cookies": cookies,
            })
        })
        .collect();

    json!({
        "schema_version": 1,
        "checksum_hex": hex(&jar.checksum),
        "pages": pages,
    })
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}
