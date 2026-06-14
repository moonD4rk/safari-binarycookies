//! Property tests: P1 structured round-trip over the builder,
//! P2 mutate-a-valid-file-and-never-panic. Fast structured exploration on
//! every `cargo test`; the coverage-guided long run lives in `fuzz/`.

#![expect(clippy::unwrap_used, reason = "tests assert by unwrapping")]

use proptest::prelude::*;
use safari_binarycookies::{cookies, from_bytes};

#[path = "common/builder.rs"]
mod builder;

use builder::{CookieSpec, build_cookie_file};

const APPLE: &[u8] = include_bytes!("../testdata/vectors/apple.binarycookies");

// Expected values computed independently of the implementation:
// the rule-5 truncation policies re-stated on the test side.
fn expected_trimmed(bytes: &[u8]) -> String {
    let trimmed = match bytes.split_last() {
        Some((&0x00, rest)) => rest,
        _ => bytes,
    };
    String::from_utf8_lossy(trimmed).into_owned()
}

fn expected_first_nul(bytes: &[u8]) -> String {
    let cut = bytes.split(|&byte| byte == 0x00).next().unwrap_or(bytes);
    String::from_utf8_lossy(cut).into_owned()
}

fn field() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 0..=200)
}

proptest! {
    // P1: any legal builder output decodes, and every field equals the input
    // after applying the rule-5 truncation for that field.
    #[test]
    fn structured_roundtrip(
        comment in proptest::option::of(field()),
        domain in field(),
        name in field(),
        path in field(),
        value in field(),
        flags in any::<u32>(),
    ) {
        let spec = CookieSpec {
            comment: comment.clone(),
            domain: domain.clone(),
            name: name.clone(),
            path: path.clone(),
            value: value.clone(),
            flags,
            expires: 0.0,
            creation: 0.0,
        };
        let file = build_cookie_file(&spec);

        let jar = from_bytes(&file);
        prop_assert!(jar.is_ok(), "builder output must decode: {:?}", jar.err());
        let jar = jar.unwrap();
        prop_assert_eq!(jar.pages.len(), 1);

        let cookie = jar.pages.first().unwrap().cookies.first().unwrap();
        prop_assert_eq!(&cookie.domain, &expected_trimmed(&domain));
        prop_assert_eq!(&cookie.name, &expected_trimmed(&name));
        prop_assert_eq!(&cookie.path, &expected_trimmed(&path));
        prop_assert_eq!(&cookie.value, &expected_first_nul(&value));
        let expected_comment = comment
            .as_deref()
            .map(|raw| String::from_utf8_lossy(raw).into_owned());
        prop_assert_eq!(&cookie.comment, &expected_comment);
        prop_assert_eq!(cookie.flags.bits(), flags);

        // Eager and lazy must agree on every Ok input.
        let lazy: Result<Vec<_>, _> = cookies(&file).and_then(Iterator::collect);
        prop_assert!(lazy.is_ok());
        prop_assert_eq!(&lazy.unwrap(), &jar.pages.first().unwrap().cookies);
    }

    // P2: flipping up to 8 bytes of a valid file must never panic — Ok and Err
    // are both acceptable, and eager/lazy must stay on the same side.
    #[test]
    fn mutated_vector_never_panics(
        flips in proptest::collection::vec((0..APPLE.len(), 1..=255u8), 1..=8),
    ) {
        let mut data = APPLE.to_vec();
        for &(index, xor) in &flips {
            if let Some(byte) = data.get_mut(index) {
                *byte ^= xor;
            }
        }
        let eager = from_bytes(&data);
        let lazy: Result<Vec<_>, _> = cookies(&data).and_then(Iterator::collect);
        match (eager, lazy) {
            (Ok(jar), Ok(lazy_cookies)) => {
                let flat: Vec<_> = jar.pages.into_iter().flat_map(|page| page.cookies).collect();
                prop_assert_eq!(flat, lazy_cookies);
            }
            (Err(_), Err(_)) => {}
            (eager, lazy) => prop_assert!(
                false,
                "eager/lazy divergence: {:?} vs {:?}",
                eager.map(|jar| jar.pages.len()),
                lazy.map(|cookies| cookies.len())
            ),
        }
    }
}
