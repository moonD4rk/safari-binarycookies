# safari-binarycookies

[![crates.io](https://img.shields.io/crates/v/safari-binarycookies.svg)](https://crates.io/crates/safari-binarycookies)
[![docs.rs](https://img.shields.io/docsrs/safari-binarycookies)](https://docs.rs/safari-binarycookies)
[![CI](https://github.com/moonD4rk/safari-binarycookies/actions/workflows/ci.yml/badge.svg)](https://github.com/moonD4rk/safari-binarycookies/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/badge/MSRV-1.88-blue)](https://blog.rust-lang.org/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/moonD4rk/safari-binarycookies#license)

A small, dependency-light, `#![forbid(unsafe_code)]` Rust library for decoding the Safari / WebKit **`Cookies.binarycookies`** cookie-jar format used on macOS and iOS (for example `~/Library/Cookies/Cookies.binarycookies`). Byte-level behavior is kept in parity with the Go reference implementation [`moond4rk/binarycookies`](https://github.com/moonD4rk/binarycookies) and verified against golden files it generates.

- **Dependency-light, safe core** — `std` + `time` + `thiserror`, `#![forbid(unsafe_code)]`, no `byteorder` / `nom`.
- **Synchronous, sans-IO core** — read a buffer, decode it; no async runtime.
- **Hardened against crafted input** — any malformed file returns an `Err`, never a panic; counts are capped before allocation.
- **Opt-in extras** — `serde` (RFC 3339 timestamps) and `display` behind additive features.

## Usage

Decode a cookie jar from disk and walk every cookie:

```rust,no_run
# #[cfg(not(feature = "std"))] fn main() {}
# #[cfg(feature = "std")]
fn main() -> Result<(), safari_binarycookies::Error> {
    let jar = safari_binarycookies::from_path("Cookies.binarycookies")?;
    for page in &jar.pages {
        for cookie in &page.cookies {
            println!(
                "{} {} = {} (secure: {}, http-only: {})",
                cookie.domain,
                cookie.name,
                cookie.value,
                cookie.is_secure(),
                cookie.is_http_only(),
            );
        }
    }
    Ok(())
}
```

Or stream cookies lazily from an in-memory buffer with [`cookies`](https://docs.rs/safari-binarycookies/latest/safari_binarycookies/fn.cookies.html), which flattens the page layer:

```rust
// A minimal valid file: `cook` magic + zero pages + 8-byte checksum.
let data = *b"cook\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

let jar = safari_binarycookies::from_bytes(&data)?;
assert!(jar.pages.is_empty());

let cookies: Result<Vec<_>, _> = safari_binarycookies::cookies(&data)?.collect();
assert!(cookies?.is_empty());
# Ok::<(), safari_binarycookies::Error>(())
```

## API at a glance

| Item | Description |
|---|---|
| `from_bytes(&[u8])` | Sans-IO core: decode a complete buffer into `BinaryCookies` |
| `cookies(&[u8])` | Lazy `Iterator<Item = Result<Cookie, Error>>` over all pages |
| `from_reader(R)` / `from_path(P)` | Convenience readers (`std` feature, on by default) |
| `BinaryCookies` / `Page` / `Cookie` / `Flags` | Plain data types with public fields |
| `BinaryCookies::cookies()` | Borrowing iterator over every cookie, flattening the page layer |
| `Cookie::{is_secure, is_http_only, expires_unix, creation_unix}` | Convenience accessors |

## Feature flags

| Feature | Default | Effect |
|---|---|---|
| `std` | ✅ | Enables `from_reader` / `from_path`; the core decoder works without it |
| `serde` | — | `Serialize` / `Deserialize` for all data types, timestamps as RFC 3339 |
| `display` | — | `impl Display for Cookie`, timestamps rendered in UTC |

Disabling `std` only removes the I/O constructors (`from_reader` / `from_path`); the crate is not `no_std` — `std` itself is always linked.

## Format notes

- Counts and sizes mix endianness by region: the file header is big-endian, everything inside pages is little-endian, timestamps are little-endian `f64` seconds since the Mac epoch (2001-01-01).
- The trailing 8-byte checksum is stored but never verified, and bytes after it (usually a `bplist00` with the cookie accept policy) are ignored — both matching the Go reference implementation.
- Out-of-range timestamps in crafted files are clamped to the years ±9999 range supported by [`time`](https://docs.rs/time); NaN decodes to the Unix epoch.

## License

Licensed under the [Apache License, Version 2.0](https://github.com/moonD4rk/safari-binarycookies/blob/main/LICENSE).

### Attribution

This crate is a Rust port of the Go implementation at [`moond4rk/binarycookies`](https://github.com/moonD4rk/binarycookies), itself a hardened fork of [cixtor/binarycookies](https://github.com/cixtor/binarycookies) (Copyright (c) 2019 CIXTOR). Provenance notes are kept in the source as `NOTES(cixtor)` comments.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this crate by you, as defined in the Apache-2.0 license, shall be licensed as above, without any additional terms or conditions.
