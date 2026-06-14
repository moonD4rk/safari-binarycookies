//! Synthetic single-cookie file builder, mirroring the Go test helper
//! `buildOneCookieFile` (`hardening_test.go:15-50`): 56-byte LE cookie header,
//! one page, caller-controlled raw field bytes including any NUL terminators.

#![expect(
    clippy::cast_possible_truncation,
    reason = "fixture fields are tiny; usize-to-u32 casts cannot truncate"
)]

#[derive(Debug, Default, Clone)]
pub(crate) struct CookieSpec {
    pub(crate) comment: Option<Vec<u8>>,
    pub(crate) domain: Vec<u8>,
    pub(crate) name: Vec<u8>,
    pub(crate) path: Vec<u8>,
    pub(crate) value: Vec<u8>,
    pub(crate) flags: u32,
    pub(crate) expires: f64,
    pub(crate) creation: f64,
}

pub(crate) fn build_cookie_file(spec: &CookieSpec) -> Vec<u8> {
    const HEADER_LEN: u32 = 56; // 10 x u32 + 2 x f64

    let comment_len = spec
        .comment
        .as_ref()
        .map_or(0, |comment| comment.len() as u32);
    let comment_offset = if spec.comment.is_some() {
        HEADER_LEN
    } else {
        0
    };
    let domain_offset = HEADER_LEN + comment_len;
    let name_offset = domain_offset + spec.domain.len() as u32;
    let path_offset = name_offset + spec.name.len() as u32;
    let value_offset = path_offset + spec.path.len() as u32;
    let size = value_offset + spec.value.len() as u32;

    let mut cookie = Vec::new();
    let header = [
        size,
        0, // unknown one
        spec.flags,
        0, // unknown two
        domain_offset,
        name_offset,
        path_offset,
        value_offset,
        comment_offset,
        0, // end-of-header marker
    ];
    for word in header {
        cookie.extend_from_slice(&word.to_le_bytes());
    }
    cookie.extend_from_slice(&spec.expires.to_le_bytes());
    cookie.extend_from_slice(&spec.creation.to_le_bytes());
    if let Some(comment) = &spec.comment {
        cookie.extend_from_slice(comment);
    }
    cookie.extend_from_slice(&spec.domain);
    cookie.extend_from_slice(&spec.name);
    cookie.extend_from_slice(&spec.path);
    cookie.extend_from_slice(&spec.value);

    let mut page = Vec::new();
    page.extend_from_slice(&[0x00, 0x00, 0x01, 0x00]); // page start tag
    page.extend_from_slice(&1u32.to_le_bytes()); // numCookies
    page.extend_from_slice(&0x10u32.to_le_bytes()); // cookie offset (ignored on decode)
    page.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // page end
    page.extend_from_slice(&cookie);

    let mut file = Vec::new();
    file.extend_from_slice(b"cook");
    file.extend_from_slice(&1u32.to_be_bytes()); // numPages
    file.extend_from_slice(&0x0cu32.to_be_bytes()); // page size (ignored on decode)
    file.extend_from_slice(&page);
    file.extend_from_slice(&[0u8; 8]); // checksum
    file
}
