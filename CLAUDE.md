# CLAUDE.md

Project-specific instructions for Claude. Global rules in `~/.claude/CLAUDE.md` still apply.

## Architecture

Rust port of the Go library `github.com/moond4rk/binarycookies`. A single library crate that decodes the Safari / WebKit `.binarycookies` cookie format. No workspace, no CLI — all code lives under `src/`. Edition 2024, MSRV 1.88.

## Development Workflow

```bash
cargo +nightly fmt --all                                  # format (nightly-only rustfmt options)
cargo clippy --all-targets --all-features -- -D warnings  # lint
cargo test --all-features                                 # test
cargo build --no-default-features                         # verify feature gates
cargo deny check                                          # supply-chain
```

Formatting requires nightly rustfmt — `rustfmt.toml` uses `group_imports` / `imports_granularity`, which are nightly-only. Only formatting needs nightly; build, test, and MSRV stay on stable.

CI runs all of these on Linux; the test suite additionally runs on macOS and Windows. Lints deny bare `#[allow]`: every suppression must be `#[expect(<lints>, reason = "...")]`, listing only the lints that actually fire.

## Core Rules

- No `unsafe` (`unsafe_code = forbid`).
- Library code uses `Result`, not `panic!` / `unwrap` / `expect`. No input may panic the decoder.
- Keep dependencies minimal; `serde` and `display` are additive opt-in features.
- New root-level files must be added to `.gitignore` (whitelist mode — root is ignored by default).
