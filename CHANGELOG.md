# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial Rust port of the Go reference implementation [`moond4rk/binarycookies`](https://github.com/moonD4rk/binarycookies): `from_bytes`, lazy `cookies` iterator, `from_reader` / `from_path` (`std` feature), with opt-in `serde` and `display` features.
