//! Decoded data model: [`BinaryCookies`], [`Page`], [`Cookie`], [`Flags`].

use core::fmt;

use time::OffsetDateTime;

/// The [`Iterator`] over every cookie in a [`BinaryCookies`], in file order,
/// returned by [`BinaryCookies::iter`] and `&BinaryCookies`'s [`IntoIterator`].
pub type CookieIter<'a> = core::iter::FlatMap<
    core::slice::Iter<'a, Page>,
    &'a Vec<Cookie>,
    fn(&'a Page) -> &'a Vec<Cookie>,
>;

/// A fully decoded `.binarycookies` file.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
// The serde impls are derive-generated, so rustdoc cannot attach a
// `doc(cfg(feature = "serde"))` badge to them on docs.rs; the feature gating is
// real regardless, and hand-writing the impls just to badge them is not worth it.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct BinaryCookies {
    /// The pages in file order, including empty ones.
    pub pages: Vec<Page>,
    /// The trailing 8-byte checksum, stored as-is and never verified, matching
    /// the Go reference implementation.
    pub checksum: [u8; 8],
}

impl BinaryCookies {
    /// Iterates over every cookie across all pages, in file order.
    ///
    /// The borrowing counterpart of the lazy [`cookies`](crate::cookies)
    /// stream, for when the file is already fully decoded.
    pub fn cookies(&self) -> impl Iterator<Item = &Cookie> {
        self.iter()
    }

    /// Borrowing iterator over every cookie across all pages, in file order.
    ///
    /// The same sequence as [`cookies`](Self::cookies) but with the nameable
    /// [`CookieIter`] return type; `&BinaryCookies` implements
    /// [`IntoIterator`] too, so `for cookie in &jar` works.
    pub fn iter(&self) -> CookieIter<'_> {
        self.pages.iter().flat_map(|page| &page.cookies)
    }
}

impl<'a> IntoIterator for &'a BinaryCookies {
    type Item = &'a Cookie;
    type IntoIter = CookieIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// A single page, grouping the cookies of one domain.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct Page {
    /// The cookies in record order.
    pub cookies: Vec<Cookie>,
    /// The page's raw cookie-offset table, kept for forensic verification.
    /// Decoding never depends on it: cookies are consumed sequentially.
    pub offsets: Vec<u32>,
}

impl Page {
    /// Borrowing iterator over this page's cookies, in record order.
    ///
    /// `&Page` implements [`IntoIterator`] too, so `for cookie in &page` works.
    pub fn iter(&self) -> core::slice::Iter<'_, Cookie> {
        self.cookies.iter()
    }
}

impl<'a> IntoIterator for &'a Page {
    type Item = &'a Cookie;
    type IntoIter = core::slice::Iter<'a, Cookie>;

    fn into_iter(self) -> Self::IntoIter {
        self.cookies.iter()
    }
}

/// A single decoded HTTP cookie.
///
/// With the `serde` feature, timestamps serialize as RFC 3339, which cannot
/// represent negative years: serializing a cookie whose crafted on-disk
/// timestamp decoded (clamped) to a year below 0000 returns a serialization
/// error — never a panic — matching Go's `time.Time` JSON marshaling limits.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct Cookie {
    /// The cookie domain, with its single trailing NUL terminator removed.
    pub domain: String,
    /// The cookie name, with its single trailing NUL terminator removed.
    pub name: String,
    /// The cookie path, with its single trailing NUL terminator removed.
    pub path: String,
    /// The cookie value, truncated at the first NUL byte.
    pub value: String,
    /// The optional cookie comment, stored verbatim (including any trailing
    /// NUL). `None` when the record's comment offset is zero.
    pub comment: Option<String>,
    /// The raw flag bits.
    pub flags: Flags,
    /// Expiration time, decoded from the on-disk Mac-epoch seconds.
    #[cfg_attr(feature = "serde", serde(with = "time::serde::rfc3339"))]
    pub expires: OffsetDateTime,
    /// Creation time, decoded from the on-disk Mac-epoch seconds.
    #[cfg_attr(feature = "serde", serde(with = "time::serde::rfc3339"))]
    pub creation: OffsetDateTime,
}

impl Cookie {
    /// Whether the `Secure` flag bit (`0x1`) is set.
    #[must_use]
    pub const fn is_secure(&self) -> bool {
        self.flags.is_secure()
    }

    /// Whether the `HttpOnly` flag bit (`0x4`) is set.
    #[must_use]
    pub const fn is_http_only(&self) -> bool {
        self.flags.is_http_only()
    }

    /// Expiration time as seconds since the Unix epoch.
    ///
    /// Out-of-range on-disk timestamps are clamped by the decoder into the
    /// range supported by [`time`] (years ±9999), so this returns the clamped
    /// value; a NaN timestamp decodes to `0`.
    #[must_use]
    pub const fn expires_unix(&self) -> i64 {
        self.expires.unix_timestamp()
    }

    /// Creation time as seconds since the Unix epoch.
    ///
    /// Clamped exactly like [`Cookie::expires_unix`].
    #[must_use]
    pub const fn creation_unix(&self) -> i64 {
        self.creation.unix_timestamp()
    }
}

/// Raw cookie flag bits with typed accessors.
///
/// Real Safari files use `0x0`, `0x1` (`Secure`), `0x4` (`HttpOnly`) or `0x5`;
/// unknown bits are preserved and readable through [`Flags::bits`].
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct Flags(u32);

impl Flags {
    /// The `Secure` bit.
    pub const SECURE: u32 = 0x1;
    /// The `HttpOnly` bit.
    pub const HTTP_ONLY: u32 = 0x4;

    pub(crate) const fn new(bits: u32) -> Self {
        Self(bits)
    }

    /// The raw flag bits as stored on disk.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Whether `bit` is fully set.
    #[must_use]
    pub const fn contains(self, bit: u32) -> bool {
        self.0 & bit == bit
    }

    /// Whether the [`Secure`](Self::SECURE) bit is set.
    #[must_use]
    pub const fn is_secure(self) -> bool {
        self.contains(Self::SECURE)
    }

    /// Whether the [`HttpOnly`](Self::HTTP_ONLY) bit is set.
    #[must_use]
    pub const fn is_http_only(self) -> bool {
        self.contains(Self::HTTP_ONLY)
    }
}

impl fmt::Debug for Flags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Flags")
            .field("bits", &format_args!("{:#x}", self.0))
            .field("secure", &self.is_secure())
            .field("http_only", &self.is_http_only())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn public_types_are_send_and_sync() {
        assert_send_sync::<BinaryCookies>();
        assert_send_sync::<Page>();
        assert_send_sync::<Cookie>();
        assert_send_sync::<Flags>();
        assert_send_sync::<crate::Error>();
        assert_send_sync::<crate::Cookies<'static>>();
    }

    #[test]
    fn flags_read_bits_via_bitmask() {
        assert!(!Flags::new(0x0).is_secure() && !Flags::new(0x0).is_http_only());
        assert!(Flags::new(0x1).is_secure() && !Flags::new(0x1).is_http_only());
        assert!(!Flags::new(0x4).is_secure() && Flags::new(0x4).is_http_only());
        assert!(Flags::new(0x5).is_secure() && Flags::new(0x5).is_http_only());
        assert_eq!(Flags::new(0x2).bits(), 0x2);
    }
}
