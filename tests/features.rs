//! Feature-gated surface tests: the serde JSON shape is a semver promise
//! locked as an exact string, and `Display` mirrors the Go `Cookie.String()`.

#![cfg(any(feature = "serde", feature = "display"))]
#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests assert on fixtures of known shape"
)]

use safari_binarycookies::{Cookie, from_bytes};

#[path = "common/builder.rs"]
mod builder;

use builder::{CookieSpec, build_cookie_file};

fn decode_one(spec: &CookieSpec) -> Cookie {
    let jar = from_bytes(&build_cookie_file(spec)).unwrap();
    jar.pages[0].cookies[0].clone()
}

// 2014-04-02T10:00:00Z as seconds since the Mac epoch (2001-01-01).
#[cfg(feature = "display")]
const DISPLAY_EXPIRES: f64 = 418_125_600.0;

#[cfg(feature = "display")]
#[test]
fn display_plain() {
    let cookie = decode_one(&CookieSpec {
        domain: b"example.com\x00".to_vec(),
        name: b"sess\x00".to_vec(),
        path: b"/\x00".to_vec(),
        value: b"abc\x00".to_vec(),
        expires: DISPLAY_EXPIRES,
        ..CookieSpec::default()
    });
    assert_eq!(
        cookie.to_string(),
        "2014-04-02 10:00:00 example.com / sess abc"
    );
}

#[cfg(feature = "display")]
#[test]
fn display_secure_httponly_comment() {
    let cookie = decode_one(&CookieSpec {
        comment: Some(b"note".to_vec()),
        domain: b"example.com\x00".to_vec(),
        name: b"sess\x00".to_vec(),
        path: b"/\x00".to_vec(),
        value: b"abc\x00".to_vec(),
        flags: 0x5,
        expires: DISPLAY_EXPIRES,
        ..CookieSpec::default()
    });
    assert_eq!(
        cookie.to_string(),
        "2014-04-02 10:00:00 example.com / sess abc Secure HttpOnly /* note */"
    );
}

#[cfg(feature = "display")]
#[test]
fn display_negative_year_pads_like_go() {
    // -64e9 Mac seconds decode to year -28; Go's time.DateTime renders the
    // year as four digits after the sign ("-0028"), not "-028".
    let cookie = decode_one(&CookieSpec {
        domain: b"d\x00".to_vec(),
        name: b"n\x00".to_vec(),
        path: b"/\x00".to_vec(),
        value: b"v\x00".to_vec(),
        expires: -64_000_000_000.0,
        ..CookieSpec::default()
    });
    assert_eq!(cookie.to_string(), "-0028-12-03 06:13:20 d / n v");
}

#[cfg(feature = "serde")]
#[test]
fn serde_negative_year_errors_without_panic() {
    // RFC 3339 cannot represent years below 0000: serialization must return
    // Err (Go's time.Time JSON marshaling fails the same way), never panic.
    let cookie = decode_one(&CookieSpec {
        domain: b"d\x00".to_vec(),
        name: b"n\x00".to_vec(),
        path: b"/\x00".to_vec(),
        value: b"v\x00".to_vec(),
        expires: f64::NEG_INFINITY,
        ..CookieSpec::default()
    });
    assert!(serde_json::to_string(&cookie).is_err());
}

#[cfg(feature = "serde")]
#[test]
fn serde_json_shape_is_locked() {
    let cookie = decode_one(&CookieSpec {
        domain: b"d\x00".to_vec(),
        name: b"n\x00".to_vec(),
        path: b"/\x00".to_vec(),
        value: b"v\x00".to_vec(),
        ..CookieSpec::default()
    });
    let json = serde_json::to_string(&cookie).unwrap();
    assert_eq!(
        json,
        r#"{"domain":"d","name":"n","path":"/","value":"v","comment":null,"flags":0,"expires":"2001-01-01T00:00:00Z","creation":"2001-01-01T00:00:00Z"}"#
    );
}

// The serde shape of the container types is a semver promise too:
// lock the `pages`/`cookies`/`offsets` field names and the checksum's
// array-of-eight-integers representation.
#[cfg(feature = "serde")]
#[test]
fn serde_jar_shape_is_locked() {
    let jar = from_bytes(&build_cookie_file(&CookieSpec {
        domain: b"d\x00".to_vec(),
        name: b"n\x00".to_vec(),
        path: b"/\x00".to_vec(),
        value: b"v\x00".to_vec(),
        ..CookieSpec::default()
    }))
    .unwrap();
    let json = serde_json::to_string(&jar).unwrap();
    assert_eq!(
        json,
        r#"{"pages":[{"cookies":[{"domain":"d","name":"n","path":"/","value":"v","comment":null,"flags":0,"expires":"2001-01-01T00:00:00Z","creation":"2001-01-01T00:00:00Z"}],"offsets":[16]}],"checksum":[0,0,0,0,0,0,0,0]}"#
    );
}

#[cfg(feature = "serde")]
#[test]
fn serde_roundtrip() {
    let cookie = decode_one(&CookieSpec {
        comment: Some(b"why\x00".to_vec()),
        domain: b"example.com\x00".to_vec(),
        name: b"sess\x00".to_vec(),
        path: b"/\x00".to_vec(),
        value: b"abc\x00".to_vec(),
        flags: 0x5,
        ..CookieSpec::default()
    });
    let json = serde_json::to_string(&cookie).unwrap();
    let back: Cookie = serde_json::from_str(&json).unwrap();
    assert_eq!(back, cookie);
}
