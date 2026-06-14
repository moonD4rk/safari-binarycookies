//! Layer A parity tests: golden full-compare against the
//! Go-generated JSON, handwritten key assertions for readable failures, the
//! negative vector, and eager/lazy consistency.

#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests assert on fixtures of known shape"
)]

use safari_binarycookies::{Error, cookies, from_bytes};
use serde_json::Value;

#[path = "common/golden.rs"]
mod golden;

const MULTIPAGE: &[u8] = include_bytes!("../testdata/vectors/multipage.binarycookies");
const APPLE: &[u8] = include_bytes!("../testdata/vectors/apple.binarycookies");
const INVALID: &[u8] = include_bytes!("../testdata/vectors/invalid.bin");
const MULTIPAGE_GOLDEN: &str = include_str!("../testdata/golden/multipage.golden.json");
const APPLE_GOLDEN: &str = include_str!("../testdata/golden/apple.golden.json");

#[test]
fn parity_multipage_golden() {
    let jar = from_bytes(MULTIPAGE).unwrap();
    let expected: Value = serde_json::from_str(MULTIPAGE_GOLDEN).unwrap();
    assert_eq!(golden::to_golden_value(&jar), expected);
}

#[test]
fn parity_apple_golden() {
    let jar = from_bytes(APPLE).unwrap();
    let expected: Value = serde_json::from_str(APPLE_GOLDEN).unwrap();
    assert_eq!(golden::to_golden_value(&jar), expected);
}

#[test]
fn parity_multipage_handwritten() {
    let jar = from_bytes(MULTIPAGE).unwrap();
    assert_eq!(jar.pages.len(), 11);
    assert_eq!(
        jar.checksum,
        [0x00, 0x00, 0x16, 0x33, 0x07, 0x17, 0x20, 0x05]
    );

    let page = &jar.pages[1];
    assert_eq!(page.offsets, [28, 121, 220, 311]);
    assert_eq!(page.cookies.len(), 4);

    let expected = [
        ("httpOnly", false, true),
        ("httpOnlySecure", true, true),
        ("normal", false, false),
        ("secure", true, false),
    ];
    for (cookie, (name, secure, http_only)) in page.cookies.iter().zip(expected) {
        assert_eq!(cookie.domain, "urlecho.appspot.com");
        assert_eq!(cookie.name, name);
        assert_eq!(cookie.path, "/");
        assert_eq!(cookie.value, "value");
        assert_eq!(cookie.comment, None);
        assert_eq!(cookie.is_secure(), secure, "cookie {name}");
        assert_eq!(cookie.is_http_only(), http_only, "cookie {name}");
    }
}

#[test]
fn parity_multipage_empty_pages() {
    let jar = from_bytes(MULTIPAGE).unwrap();
    for index in [0, 2, 3, 4, 5, 6, 7, 8, 9, 10] {
        let page = &jar.pages[index];
        assert!(
            page.cookies.is_empty(),
            "page {index} should have no cookies"
        );
        assert!(
            page.offsets.is_empty(),
            "page {index} should have no offsets"
        );
    }
}

#[test]
fn parity_apple_handwritten() {
    let jar = from_bytes(APPLE).unwrap();
    assert_eq!(jar.pages.len(), 2);
    assert_eq!(
        jar.checksum,
        [0x00, 0x00, 0x36, 0x69, 0x07, 0x17, 0x20, 0x05]
    );

    let page = &jar.pages[0];
    assert_eq!(page.offsets, [40, 153, 229, 316, 414, 523, 642]);
    let names: Vec<&str> = page.cookies.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "dssid2",
            "pxro",
            "s_invisit_n2_us",
            "s_pathLength",
            "s_pv",
            "s_vi",
            "s_vnum_n2_us"
        ]
    );
    for cookie in &page.cookies {
        assert_eq!(cookie.domain, ".apple.com");
        assert_eq!(cookie.path, "/");
        assert!(!cookie.is_secure() && !cookie.is_http_only());
    }
    assert_eq!(
        page.cookies[0].value,
        "b267acef-b91e-4a5e-8f15-54be2c037b1c"
    );
    assert_eq!(
        page.cookies[5].value,
        "[CS]v1|28ADA9F785011356-60001602602D90C1[CE]"
    );
    assert_eq!(page.cookies[0].expires_unix(), 1_396_475_762);
    assert_eq!(page.cookies[0].creation_unix(), 1_364_939_762);

    let store = &jar.pages[1];
    assert_eq!(store.offsets, [20, 217]);
    assert_eq!(store.cookies[0].name, "asmetrics");
    assert_eq!(
        store.cookies[0].value,
        "%257B%2522store%2522%253A%257B%2522sid%2522%253A%2522wHF2F2PHCCCX72KDY%2522%252C%2522vh%2522%253Atrue%257D%257D"
    );
    assert_eq!(store.cookies[1].name, "dc");
    assert_eq!(store.cookies[1].value, "nwk");
    assert_eq!(store.cookies[1].domain, ".store.apple.com");
}

#[test]
fn parity_invalid_signature() {
    assert!(matches!(
        from_bytes(INVALID),
        Err(Error::InvalidSignature(signature)) if signature == *b"Thes"
    ));
}

#[test]
fn parity_eager_lazy_consistency() {
    for vector in [MULTIPAGE, APPLE] {
        let eager: Vec<_> = from_bytes(vector)
            .unwrap()
            .pages
            .into_iter()
            .flat_map(|page| page.cookies)
            .collect();
        let lazy: Vec<_> = cookies(vector).unwrap().collect::<Result<_, _>>().unwrap();
        assert_eq!(eager, lazy);
    }
}
