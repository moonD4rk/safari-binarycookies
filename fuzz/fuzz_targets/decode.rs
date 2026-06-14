//! Single fuzz target feeding both decode paths.
//!
//! Invariants, any violation crashes: no input panics, allocation stays
//! bounded by the count caps, and the eager and lazy paths agree — equal
//! cookies in the Ok domain, both Err in the Err domain.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let eager = safari_binarycookies::from_bytes(data);
    let lazy: Result<Vec<safari_binarycookies::Cookie>, safari_binarycookies::Error> =
        safari_binarycookies::cookies(data).and_then(|iter| iter.collect());

    match (eager, lazy) {
        (Ok(jar), Ok(lazy_cookies)) => {
            let flat: Vec<_> = jar.pages.iter().flat_map(|page| page.cookies.iter()).collect();
            assert_eq!(flat.len(), lazy_cookies.len());
            for (eager_cookie, lazy_cookie) in flat.iter().zip(&lazy_cookies) {
                assert_eq!(*eager_cookie, lazy_cookie);
            }
        }
        (Err(_), Err(_)) => {}
        (eager, lazy) => panic!("eager/lazy divergence: {eager:?} vs {lazy:?}"),
    }
});
