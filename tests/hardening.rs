//! Layer B hardening tests: the Go `hardening_test.go` port table plus the
//! Rust-only cases the type system forces, plus the stable fuzz-seed
//! regression loop.

#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests assert on fixtures of known shape"
)]

use safari_binarycookies::{Component, Error, cookies, from_bytes};

#[path = "common/builder.rs"]
mod builder;

use builder::{CookieSpec, build_cookie_file};

const APPLE: &[u8] = include_bytes!("../testdata/vectors/apple.binarycookies");
const MULTIPAGE: &[u8] = include_bytes!("../testdata/vectors/multipage.binarycookies");

fn spec_with_value() -> CookieSpec {
    CookieSpec {
        domain: b"d\x00".to_vec(),
        name: b"n\x00".to_vec(),
        path: b"/\x00".to_vec(),
        value: b"v\x00".to_vec(),
        ..CookieSpec::default()
    }
}

// Port of TestRejectsHugeCookieCount (hardening_test.go:54): numCookies =
// 0xe8000000 must be rejected before any allocation.
#[test]
fn rejects_huge_cookie_count() {
    let input = [
        b'c', b'o', b'o', b'k', //
        0x00, 0x00, 0x00, 0x01, // numPages (BE)
        0x00, 0x00, 0x00, 0x0c, // page size (BE, ignored)
        0x00, 0x00, 0x01, 0x00, // page start tag
        0x00, 0x00, 0x00, 0xe8, // numCookies = 0xe8000000 (LE)
    ];
    assert!(matches!(
        from_bytes(&input),
        Err(Error::TooManyCookies(0xe800_0000))
    ));
}

// Port of TestRejectsHugePageCount (hardening_test.go:69).
#[test]
fn rejects_huge_page_count() {
    let input = [b'c', b'o', b'o', b'k', 0x7f, 0xff, 0xff, 0xff];
    assert!(matches!(
        from_bytes(&input),
        Err(Error::TooManyPages(0x7fff_ffff))
    ));
}

// Port of TestEmptyFieldDoesNotPanic (hardening_test.go:82): a zero-length
// domain/name/path has no terminator to strip and must decode to "".
#[test]
fn empty_field_does_not_panic() {
    type ClearField = fn(&mut CookieSpec);
    type ReadField = fn(&safari_binarycookies::Cookie) -> &str;
    let cases: [(&str, ClearField, ReadField); 3] = [
        (
            "empty domain",
            |spec| spec.domain = Vec::new(),
            |c| &c.domain,
        ),
        ("empty name", |spec| spec.name = Vec::new(), |c| &c.name),
        ("empty path", |spec| spec.path = Vec::new(), |c| &c.path),
    ];
    for (label, clear_field, read_field) in cases {
        let mut spec = spec_with_value();
        clear_field(&mut spec);
        let jar = from_bytes(&build_cookie_file(&spec)).unwrap();
        assert_eq!(jar.pages.len(), 1, "{label}");
        assert_eq!(jar.pages[0].cookies.len(), 1, "{label}");
        let cookie = &jar.pages[0].cookies[0];
        assert_eq!(
            read_field(cookie),
            "",
            "{label}: cleared field must decode to empty"
        );
        assert_eq!(cookie.value, "v", "{label}: untouched value must survive");
    }
}

// Port of TestDecodeChunkedReader (hardening_test.go:110): a reader yielding
// one byte per call must still decode through read_to_end.
#[cfg(feature = "std")]
#[test]
fn decode_chunked_reader() {
    use std::io::Read;

    struct OneByteReader<R>(R);

    impl<R: Read> Read for OneByteReader<R> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let len = buf.len().min(1);
            self.0.read(&mut buf[..len])
        }
    }

    let jar = safari_binarycookies::from_reader(OneByteReader(APPLE)).unwrap();
    // The chunked reader path must decode byte-identically to the sans-IO core.
    assert_eq!(jar, from_bytes(APPLE).unwrap());
}

// Port of TestTruncatedInputReturnsError (hardening_test.go:125), upgraded to
// exhaust every proper prefix.
#[test]
fn truncated_input_returns_error() {
    for n in 0..APPLE.len() {
        assert!(
            from_bytes(&APPLE[..n]).is_err(),
            "prefix of {n} bytes must not decode"
        );
    }
}

// Non-monotonic offsets surface as MalformedOffsets via checked_sub instead
// of Go's u32 wraparound.
#[test]
fn non_monotonic_offsets_are_malformed() {
    let mut input = build_cookie_file(&spec_with_value());
    input[48..52].copy_from_slice(&10u32.to_le_bytes()); // nameOffset = 10 < domainOffset = 56
    assert!(matches!(from_bytes(&input), Err(Error::MalformedOffsets)));
}

// With no comment, the first component diff (domainOffset - 0) still
// participates in validation — the telescoping sum cannot be shortcut.
#[test]
fn telescoping_check_covers_missing_comment() {
    let mut input = build_cookie_file(&spec_with_value());
    input[44..48].copy_from_slice(&5000u32.to_le_bytes()); // domainOffset = 5000 > 4096
    assert!(matches!(
        from_bytes(&input),
        Err(Error::CookieTooLarge {
            component: Component::Comment,
            size: 5000
        })
    ));
}

// Five components each within the cap whose sum exceeds it.
#[test]
fn oversized_component_total_is_rejected() {
    let spec = CookieSpec {
        comment: Some(vec![b'c'; 1000]),
        domain: vec![b'd'; 1000],
        name: vec![b'n'; 1000],
        path: vec![b'p'; 1000],
        value: vec![b'v'; 1000],
        ..CookieSpec::default()
    };
    assert!(matches!(
        from_bytes(&build_cookie_file(&spec)),
        Err(Error::CookieTotalTooLarge(5000))
    ));
}

// NaN timestamps decode to the Unix epoch (saturating cast).
#[test]
fn nan_timestamp_decodes_to_epoch() {
    let spec = CookieSpec {
        expires: f64::NAN,
        ..spec_with_value()
    };
    let jar = from_bytes(&build_cookie_file(&spec)).unwrap();
    assert_eq!(jar.pages[0].cookies[0].expires_unix(), 0);
}

// Infinite / astronomical timestamps clamp to time's bounds — never a panic,
// never an error.
#[test]
fn extreme_timestamps_clamp() {
    for (expires, expected) in [
        (f64::INFINITY, 253_402_300_799),
        (1e300, 253_402_300_799),
        (f64::NEG_INFINITY, -377_705_116_800),
    ] {
        let spec = CookieSpec {
            expires,
            ..spec_with_value()
        };
        let jar = from_bytes(&build_cookie_file(&spec)).unwrap();
        assert_eq!(
            jar.pages[0].cookies[0].expires_unix(),
            expected,
            "expires {expires}"
        );
    }
}

// A comment offset whose u32 wrap distance lands in [1, 4096] decodes Ok in Go
// (the wrapped length passes the cap and is read); checked_sub rejects every
// non-monotonic pair here instead.
#[test]
fn wrap_window_comment_offset_is_rejected() {
    let mut input = Vec::new();
    input.extend_from_slice(b"cook");
    input.extend_from_slice(&1u32.to_be_bytes());
    input.extend_from_slice(&0x0cu32.to_be_bytes());
    input.extend_from_slice(&[0x00, 0x00, 0x01, 0x00]);
    input.extend_from_slice(&1u32.to_le_bytes());
    input.extend_from_slice(&0x10u32.to_le_bytes());
    input.extend_from_slice(&[0x00; 4]);
    // size and all four string offsets 0, commentOffset 10 short of wrapping
    for word in [0u32, 0, 0, 0, 0, 0, 0, 0, 0xFFFF_FFF6, 0] {
        input.extend_from_slice(&word.to_le_bytes());
    }
    input.extend_from_slice(&[0u8; 16]); // expires + creation
    input.extend_from_slice(b"ABCDEFGHIJ"); // the 10 bytes Go reads as comment
    input.extend_from_slice(&[0u8; 8]); // checksum
    assert!(matches!(from_bytes(&input), Err(Error::MalformedOffsets)));
}

// A cookie count within the cap but larger than the remaining input must fail
// before the offset table is allocated; UnexpectedEof is the locked variant.
#[test]
fn claimed_count_beyond_remaining_input() {
    let mut input = Vec::new();
    input.extend_from_slice(b"cook");
    input.extend_from_slice(&1u32.to_be_bytes());
    input.extend_from_slice(&0x0cu32.to_be_bytes());
    input.extend_from_slice(&[0x00, 0x00, 0x01, 0x00]);
    input.extend_from_slice(&1000u32.to_le_bytes()); // within cap, but no offset bytes follow
    assert!(matches!(from_bytes(&input), Err(Error::UnexpectedEof)));
}

// The value is truncated at its first embedded NUL.
#[test]
fn value_truncates_at_embedded_nul() {
    let spec = CookieSpec {
        value: b"abc\x00tail".to_vec(),
        ..spec_with_value()
    };
    let jar = from_bytes(&build_cookie_file(&spec)).unwrap();
    assert_eq!(jar.pages[0].cookies[0].value, "abc");
}

// The comment keeps a trailing NUL verbatim (never trimmed).
#[test]
fn comment_keeps_terminator() {
    let spec = CookieSpec {
        comment: Some(b"note\x00".to_vec()),
        ..spec_with_value()
    };
    let jar = from_bytes(&build_cookie_file(&spec)).unwrap();
    assert_eq!(jar.pages[0].cookies[0].comment.as_deref(), Some("note\x00"));
}

// Decision: the lazy iterator mirrors the eager decoder's trailing-checksum
// read, so both paths fail identically on a truncated trailer; afterwards the
// iterator honors its fused contract.
#[test]
fn lazy_truncated_trailer_matches_eager() {
    let mut input = build_cookie_file(&spec_with_value());
    input.truncate(input.len() - 5); // cut into the 8-byte checksum

    assert!(matches!(from_bytes(&input), Err(Error::UnexpectedEof)));

    let mut lazy = cookies(&input).unwrap();
    assert!(
        matches!(lazy.next(), Some(Ok(_))),
        "the one cookie still parses"
    );
    assert!(
        matches!(lazy.next(), Some(Err(Error::UnexpectedEof))),
        "the truncated checksum must surface as a final error"
    );
    assert!(lazy.next().is_none(), "iterator fuses after the error");
    assert!(lazy.next().is_none(), "and stays fused");
}

// Same trailer rule for an empty jar: zero pages still require the checksum.
#[test]
fn lazy_empty_jar_requires_checksum() {
    let input = *b"cook\x00\x00\x00\x00\x00\x00\x00"; // 0 pages, 3-byte trailer

    assert!(matches!(from_bytes(&input), Err(Error::UnexpectedEof)));

    let mut lazy = cookies(&input).unwrap();
    assert!(matches!(lazy.next(), Some(Err(Error::UnexpectedEof))));
    assert!(lazy.next().is_none());
}

// The lazy path must reject a bad page tag exactly like the eager path and
// fuse afterwards.
#[test]
fn lazy_bad_page_tag_fuses() {
    let mut input = build_cookie_file(&spec_with_value());
    input[12..16].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);

    assert!(matches!(from_bytes(&input), Err(Error::InvalidPageTag)));

    let mut lazy = cookies(&input).unwrap();
    assert!(matches!(lazy.next(), Some(Err(Error::InvalidPageTag))));
    assert!(lazy.next().is_none());
}

// rule 7: the page-end marker (00 00 00 00 after the cookie-offset table) is
// matched as raw bytes; a non-zero marker must be rejected, just like the
// magic and the page tag already are.
#[test]
fn invalid_page_end_is_rejected() {
    let mut input = build_cookie_file(&spec_with_value());
    input[24..28].copy_from_slice(&[0x01, 0x00, 0x00, 0x00]); // page-end marker
    assert!(matches!(from_bytes(&input), Err(Error::InvalidPageEnd)));
}

// rule 7: the all-zero cookie-header-end marker is matched as raw bytes; a
// non-zero marker must be rejected.
#[test]
fn invalid_cookie_header_end_is_rejected() {
    let mut input = build_cookie_file(&spec_with_value());
    input[64..68].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // cookie-header-end marker
    assert!(matches!(
        from_bytes(&input),
        Err(Error::InvalidCookieHeaderEnd)
    ));
}

// from_path is the only entry point touching the filesystem: cover both the
// happy path and the Error::Io path.
#[cfg(feature = "std")]
#[test]
fn from_path_reads_and_reports_io_errors() {
    let path = std::env::temp_dir().join(format!(
        "safari_binarycookies_test_{}_{:?}.binarycookies",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::write(&path, APPLE).unwrap();
    let jar = safari_binarycookies::from_path(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    // from_path must decode byte-identically to the sans-IO core.
    assert_eq!(jar, from_bytes(APPLE).unwrap());

    assert!(matches!(
        safari_binarycookies::from_path(&path),
        Err(Error::Io(_))
    ));
}

// Flags outside {0,1,4,5} are read per-bit here, where Go's switch leaves both
// booleans false; lock the Rust side of the divergence domain so the bitmask
// semantics cannot regress silently.
#[test]
fn unknown_flag_bits_read_via_bitmask() {
    for (flags, secure, http_only) in [
        (0x2_u32, false, false),
        (0x3, true, false),
        (0x6, false, true),
        (0x7, true, true),
    ] {
        let spec = CookieSpec {
            flags,
            ..spec_with_value()
        };
        let jar = from_bytes(&build_cookie_file(&spec)).unwrap();
        let cookie = &jar.pages[0].cookies[0];
        assert_eq!(cookie.flags.bits(), flags);
        assert_eq!(cookie.is_secure(), secure, "flags {flags:#x}");
        assert_eq!(cookie.is_http_only(), http_only, "flags {flags:#x}");
    }
}

// The rustdoc on `Cookies` promises that a clone resumes from the current
// position; lock that contract.
#[test]
fn lazy_clone_resumes_mid_stream() {
    let mut original = cookies(MULTIPAGE).unwrap();
    let first = original.next().unwrap().unwrap();

    let clone = original.clone();
    let rest_original: Vec<_> = original.collect::<Result<_, _>>().unwrap();
    let rest_clone: Vec<_> = clone.collect::<Result<_, _>>().unwrap();

    assert_eq!(rest_original.len(), 3, "multipage holds 4 cookies in total");
    assert_eq!(rest_original, rest_clone);
    assert_ne!(Some(&first), rest_clone.first(), "clone must not restart");
}

// The committed fuzz corpus is exactly the vendored testdata (5 unpacked Go
// seeds + 3 vectors); regeneration must keep them in lockstep.
#[test]
fn fuzz_corpus_matches_testdata() {
    let pairs: [(&str, &[u8], &[u8]); 8] = [
        (
            "110b6c905d7b0d0a",
            include_bytes!("../fuzz/corpus/decode/110b6c905d7b0d0a"),
            include_bytes!("../testdata/fuzz-raw/110b6c905d7b0d0a"),
        ),
        (
            "910d4bf3b3a13d8c",
            include_bytes!("../fuzz/corpus/decode/910d4bf3b3a13d8c"),
            include_bytes!("../testdata/fuzz-raw/910d4bf3b3a13d8c"),
        ),
        (
            "e546dbacc5f4ccab",
            include_bytes!("../fuzz/corpus/decode/e546dbacc5f4ccab"),
            include_bytes!("../testdata/fuzz-raw/e546dbacc5f4ccab"),
        ),
        (
            "fe9f4dd747d34d56",
            include_bytes!("../fuzz/corpus/decode/fe9f4dd747d34d56"),
            include_bytes!("../testdata/fuzz-raw/fe9f4dd747d34d56"),
        ),
        (
            "oom_huge_numcookies",
            include_bytes!("../fuzz/corpus/decode/oom_huge_numcookies"),
            include_bytes!("../testdata/fuzz-raw/oom_huge_numcookies"),
        ),
        (
            "vector_apple",
            include_bytes!("../fuzz/corpus/decode/vector_apple"),
            APPLE,
        ),
        (
            "vector_invalid",
            include_bytes!("../fuzz/corpus/decode/vector_invalid"),
            include_bytes!("../testdata/vectors/invalid.bin"),
        ),
        (
            "vector_multipage",
            include_bytes!("../fuzz/corpus/decode/vector_multipage"),
            MULTIPAGE,
        ),
    ];
    for (name, corpus, testdata) in pairs {
        assert_eq!(
            corpus, testdata,
            "fuzz corpus seed {name} drifted from its testdata source"
        );
    }
}

// Every fuzz seed must decode without panicking on stable, on every CI run;
// the OOM regression seed must fail fast via the count guard.
#[test]
fn fuzz_seed_regression() {
    let seeds: [(&str, &[u8]); 5] = [
        (
            "110b6c905d7b0d0a",
            include_bytes!("../testdata/fuzz-raw/110b6c905d7b0d0a"),
        ),
        (
            "910d4bf3b3a13d8c",
            include_bytes!("../testdata/fuzz-raw/910d4bf3b3a13d8c"),
        ),
        (
            "e546dbacc5f4ccab",
            include_bytes!("../testdata/fuzz-raw/e546dbacc5f4ccab"),
        ),
        (
            "fe9f4dd747d34d56",
            include_bytes!("../testdata/fuzz-raw/fe9f4dd747d34d56"),
        ),
        (
            "oom_huge_numcookies",
            include_bytes!("../testdata/fuzz-raw/oom_huge_numcookies"),
        ),
    ];
    for (name, seed) in seeds {
        let eager = from_bytes(seed);
        let lazy: Result<Vec<_>, _> = cookies(seed).and_then(Iterator::collect);
        assert!(
            eager.is_err(),
            "seed {name} is a crafted-input regression and must not decode"
        );
        assert!(lazy.is_err(), "seed {name} must also fail lazily");
    }
    let oom: &[u8] = include_bytes!("../testdata/fuzz-raw/oom_huge_numcookies");
    assert!(matches!(
        from_bytes(oom),
        Err(Error::TooManyCookies(0xe800_0000))
    ));
}
