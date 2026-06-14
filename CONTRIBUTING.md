# Contributing

Thanks for considering a contribution. This is a Rust library that decodes the Safari / WebKit `.binarycookies` format, modeled after the Go library at <https://github.com/moonD4rk/binarycookies>.

## Before You Start

1. **For non-trivial changes, open an issue first.** Anything that adds, removes, or reshapes the public API, or changes a default, should be discussed in an issue before the PR.

2. **Trivial changes are fine to PR directly** — typos, doc fixes, dependency bumps, small refactors.

## Development Workflow

```bash
# Format (nightly-only rustfmt options)
cargo +nightly fmt --all

# Lint (CI uses -D warnings; match this locally)
cargo clippy --all-targets --all-features -- -D warnings

# Test
cargo test --all-features

# Build without default features (verifies the std / serde feature gates)
cargo build --no-default-features

# Supply-chain check (requires cargo-deny; install via `cargo install cargo-deny`)
cargo deny check
```

CI runs these gates on Linux; the test suite additionally runs on macOS and Windows, plus an MSRV (1.88) test job. No `rust-toolchain.toml` is committed: use any stable toolchain ≥ 1.88 with the `clippy` and `rustfmt` components; only the formatting step needs nightly rustfmt.

## Coding Conventions

- **No `unsafe` code.** The crate forbids it via the lint set.
- **The decoder must never panic on any input.** Malformed files return `Err(Error)`, never abort. This is a hard invariant (fuzzed).
- **No `.unwrap()` / `.expect()` / `panic!()` in library code.** Bubble errors via `Result<T, Error>`. Tests are allowed to unwrap.
- **Keep the decode path dependency-light.** `std` + `time` + `thiserror`; `serde` / `display` are additive opt-in features. No CLI dependencies in the crate.
- **Default to no comments.** Use self-documenting names. Add a comment only when the *why* is non-obvious.

## Commit Messages

- Imperative present tense, ≤ 72 characters in the subject.
- Body explains *why*, not *what* — the diff already shows what.

## License

By contributing, you agree your contribution is licensed under the [Apache License, Version 2.0](LICENSE), same as the project, without any additional terms or conditions.
