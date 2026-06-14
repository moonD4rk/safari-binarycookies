# Security Policy

## Scope

`safari-binarycookies` is a decoder for an untrusted file format: a `.binarycookies` jar may originate from another machine. Parsing such a file is the crate's intended function.

In scope are defects in this codebase that could harm a legitimate user — for example a crafted `.binarycookies` file that causes a crash, a panic in library code (the decoder is `panic`-free by contract — any input must return `Err`, not abort), or a memory-safety issue (the crate is `#![forbid(unsafe_code)]`, so any such finding is high priority).

## Reporting a Vulnerability

Please report privately via GitHub's **"Report a vulnerability"** button under the repository's *Security* tab, rather than opening a public issue.

Include the affected version, a description, and a minimal reproduction (ideally the offending `.binarycookies` bytes) if you have one. You can expect an initial response within a few days.

## Supported Versions

Security fixes target the latest released `0.x` line.
