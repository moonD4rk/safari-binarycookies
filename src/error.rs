//! Decode-failure taxonomy for the `.binarycookies` format.

/// Which of the five cookie string components overflowed the size cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Component {
    /// The comment region (`commentOffset..domainOffset`).
    Comment,
    /// The domain field.
    Domain,
    /// The name field.
    Name,
    /// The path field.
    Path,
    /// The value field.
    Value,
}

impl core::fmt::Display for Component {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Comment => "comment",
            Self::Domain => "domain",
            Self::Name => "name",
            Self::Path => "path",
            Self::Value => "value",
        })
    }
}

/// Errors produced while decoding a `.binarycookies` file.
///
/// Every malformed input maps to a variant here; the decoder never panics.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The underlying reader failed; only `from_reader` / `from_path` produce this.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// The file does not start with the `cook` magic; carries the four bytes found.
    #[error("invalid signature: {0:?}")]
    InvalidSignature([u8; 4]),

    /// A page does not start with the `00 00 01 00` tag.
    #[error("invalid page tag")]
    InvalidPageTag,

    /// A page header does not end with the `00 00 00 00` marker.
    #[error("invalid page end")]
    InvalidPageEnd,

    /// A cookie header does not end with the `00 00 00 00` marker.
    #[error("invalid cookie header end")]
    InvalidCookieHeaderEnd,

    /// The input ended before the structure it declares was fully read.
    #[error("unexpected end of input")]
    UnexpectedEof,

    /// The declared page count exceeds the hardening cap of 65 536.
    #[error("page count too large: {0}")]
    TooManyPages(u32),

    /// The declared per-page cookie count exceeds the hardening cap of 1 048 576.
    #[error("cookie count too large: {0}")]
    TooManyCookies(u32),

    /// One of the five cookie components is longer than 4096 bytes.
    #[error("cookie {component} component too large: {size}")]
    CookieTooLarge {
        /// Which component overflowed.
        component: Component,
        /// Length of the offending component in bytes.
        size: u32,
    },

    /// The five cookie components together exceed 4096 bytes.
    #[error("cookie total size too large: {0}")]
    CookieTotalTooLarge(u32),

    /// Cookie string offsets are not monotonically increasing.
    #[error("malformed cookie offsets")]
    MalformedOffsets,
}
