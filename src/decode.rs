//! Sequential decoder for the `.binarycookies` byte format.
//!
//! Each `rule N` comment anchors a byte-level decoding rule; the rule set is
//! the parity contract with the Go reference implementation.

use time::OffsetDateTime;

use crate::cursor::Cursor;
use crate::error::{Component, Error};
use crate::model::{BinaryCookies, Cookie, Flags, Page};

const MAGIC: [u8; 4] = *b"cook";
const PAGE_TAG: [u8; 4] = [0x00, 0x00, 0x01, 0x00];
const ZERO_TAG: [u8; 4] = [0x00; 4];

// Hardening caps on counts read straight from the file, far above any real
// Safari jar; crafted counts are rejected before anything is allocated.
const MAX_PAGES: u32 = 1 << 16;
const MAX_COOKIES_PER_PAGE: u32 = 1 << 20;
// RFC 2965-derived bound on each cookie component and on their sum.
const MAX_COOKIE_SIZE: u32 = 4096;

// NOTES(cixtor): Unix seconds at the Mac epoch (2001-01-01T00:00:00Z); on-disk
// timestamps are seconds since that epoch.
const MAC_EPOCH_OFFSET: f64 = 978_307_200.0;
// Accepted domain of `OffsetDateTime::from_unix_timestamp` (years -9999..=9999).
const MIN_UNIX_TIMESTAMP: i64 = -377_705_116_800;
const MAX_UNIX_TIMESTAMP: i64 = 253_402_300_799;

/// Decodes a complete `.binarycookies` file from a byte slice.
///
/// This is the sans-IO core: pure slice parsing, no I/O, no seeking. Pages and
/// cookies are consumed sequentially in file order; bytes after the trailing
/// checksum (typically a `bplist00` blob) are ignored. Malformed input returns
/// an [`Error`], never panics.
///
/// # Errors
///
/// Returns the first structural violation found: a bad magic or marker, a
/// count above the hardening caps, non-monotonic string offsets, an oversized
/// cookie, or truncated input.
///
/// # Examples
///
/// ```
/// // A minimal file: `cook` magic + zero pages + 8-byte checksum.
/// let data = *b"cook\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
/// let jar = safari_binarycookies::from_bytes(&data)?;
/// assert!(jar.pages.is_empty());
/// assert_eq!(jar.checksum, [0; 8]);
/// # Ok::<(), safari_binarycookies::Error>(())
/// ```
pub fn from_bytes(input: &[u8]) -> Result<BinaryCookies, Error> {
    let mut decoder = Decoder::new(input);

    decoder.signature()?;
    let page_count = decoder.page_count()?;
    decoder.skip_page_size_table(page_count)?;

    // Grown per parsed page instead of pre-allocated from the declared count,
    // so memory tracks input actually consumed.
    let mut pages = Vec::new();
    for _ in 0..page_count {
        pages.push(decoder.page()?);
    }

    let checksum = decoder.checksum()?;

    // NOTES(cixtor): bytes after the checksum are an optional bplist00 (e.g.
    // NSHTTPCookieAcceptPolicy) and are deliberately left unread.
    Ok(BinaryCookies { pages, checksum })
}

// Format layer over `Cursor`: each field read is a method here, while `Cursor`
// stays the sole place raw bytes are sliced. The eager `from_bytes` decode and
// the lazy `cookies` stream drive the same methods.
#[derive(Debug, Clone)]
pub(crate) struct Decoder<'a> {
    cursor: Cursor<'a>,
}

impl<'a> Decoder<'a> {
    pub(crate) const fn new(input: &'a [u8]) -> Self {
        Self {
            cursor: Cursor::new(input),
        }
    }

    // rule 7: the magic is matched as raw bytes, never endian-decoded.
    pub(crate) fn signature(&mut self) -> Result<(), Error> {
        let signature: [u8; 4] = self.cursor.array()?;
        if signature == MAGIC {
            Ok(())
        } else {
            Err(Error::InvalidSignature(signature))
        }
    }

    // rule 1: the page count is big-endian; the cap rejects allocation bombs.
    pub(crate) fn page_count(&mut self) -> Result<u32, Error> {
        let count = self.cursor.u32_be()?;
        if count > MAX_PAGES {
            return Err(Error::TooManyPages(count));
        }
        Ok(count)
    }

    // rule 1 + rule 11: the page-size table is big-endian and only ever skipped
    // — pages are consumed sequentially, never located through the table.
    pub(crate) fn skip_page_size_table(&mut self, page_count: u32) -> Result<(), Error> {
        self.cursor.skip(table_len(page_count)?)
    }

    fn page(&mut self) -> Result<Page, Error> {
        self.page_tag()?;
        let cookie_count = self.cookie_count()?;
        // rule 2: cookie offsets are little-endian; stored verbatim,
        // decoding does not depend on them.
        let offsets = (0..cookie_count)
            .map(|_| self.cursor.u32_le())
            .collect::<Result<Vec<u32>, Error>>()?;
        self.page_end()?;

        let mut cookies = Vec::new();
        for _ in 0..cookie_count {
            cookies.push(self.cookie()?);
        }
        Ok(Page { cookies, offsets })
    }

    // rule 7: fixed page markers are matched as raw bytes.
    pub(crate) fn page_tag(&mut self) -> Result<(), Error> {
        self.cursor.expect_tag(PAGE_TAG, Error::InvalidPageTag)
    }

    pub(crate) fn page_end(&mut self) -> Result<(), Error> {
        self.cursor.expect_tag(ZERO_TAG, Error::InvalidPageEnd)
    }

    // rule 2: the cookie count is little-endian. The cap plus the
    // remaining-input pre-check reject crafted counts before the offset table
    // is allocated.
    pub(crate) fn cookie_count(&mut self) -> Result<u32, Error> {
        let count = self.cursor.u32_le()?;
        if count > MAX_COOKIES_PER_PAGE {
            return Err(Error::TooManyCookies(count));
        }
        if table_len(count)? > self.cursor.remaining() {
            return Err(Error::UnexpectedEof);
        }
        Ok(count)
    }

    pub(crate) fn skip_cookie_offset_table(&mut self, count: u32) -> Result<(), Error> {
        self.cursor.skip(table_len(count)?)
    }

    // rule 10: the checksum is stored, never computed or verified.
    pub(crate) fn checksum(&mut self) -> Result<[u8; 8], Error> {
        self.cursor.array()
    }

    pub(crate) fn cookie(&mut self) -> Result<Cookie, Error> {
        // rule 2: every u32 in the cookie header is little-endian.
        let size = self.cursor.u32_le()?;
        // NOTES(cixtor): two 4-byte fields of unknown purpose surround the
        // flags; read and discarded.
        self.cursor.skip(4)?;
        // rule 9: flags are exposed as raw bits and read via bitmask.
        let flags = Flags::new(self.cursor.u32_le()?);
        self.cursor.skip(4)?;
        let domain_offset = self.cursor.u32_le()?;
        let name_offset = self.cursor.u32_le()?;
        let path_offset = self.cursor.u32_le()?;
        let value_offset = self.cursor.u32_le()?;
        let comment_offset = self.cursor.u32_le()?;
        // rule 7: the cookie header ends with a fixed all-zero marker.
        self.cursor
            .expect_tag(ZERO_TAG, Error::InvalidCookieHeaderEnd)?;
        // rule 3: timestamps are little-endian float64. The bundled Hex Fiend
        // template writes them big-endian; the Go reference reads little-endian
        // and is authoritative.
        let expires = mac_epoch_time(self.cursor.f64_le()?);
        let creation = mac_epoch_time(self.cursor.f64_le()?);

        // rule 8: all five component lengths are validated before any string is
        // read; the same five differences are the read lengths below. The first
        // difference participates even when there is no comment.
        let comment_len = component_len(Component::Comment, comment_offset, domain_offset)?;
        let domain_len = component_len(Component::Domain, domain_offset, name_offset)?;
        let name_len = component_len(Component::Name, name_offset, path_offset)?;
        let path_len = component_len(Component::Path, path_offset, value_offset)?;
        let value_len = component_len(Component::Value, value_offset, size)?;
        let total = comment_len + domain_len + name_len + path_len + value_len;
        if total > MAX_COOKIE_SIZE {
            return Err(Error::CookieTotalTooLarge(total));
        }

        // rule 6: a zero comment offset means no comment; no bytes are consumed.
        let comment = if comment_offset == 0 {
            None
        } else {
            // rule 5: the comment keeps any trailing NUL verbatim.
            Some(lossy(self.cursor.take(to_len(comment_len)?)?))
        };
        // rule 5: domain/name/path drop exactly one trailing NUL.
        let domain = trim_terminator(self.cursor.take(to_len(domain_len)?)?);
        let name = trim_terminator(self.cursor.take(to_len(name_len)?)?);
        let path = trim_terminator(self.cursor.take(to_len(path_len)?)?);
        // rule 5: the value is cut at the first NUL. Its declared length may
        // extend past the terminator into trailing metadata, so the full length
        // is consumed to keep the stream aligned for the next record.
        let value = truncate_at_nul(self.cursor.take(to_len(value_len)?)?);

        Ok(Cookie {
            domain,
            name,
            path,
            value,
            comment,
            flags,
            expires,
            creation,
        })
    }
}

// rule 8: explicit checked_sub instead of Go's u32 wraparound-then-cap; a
// non-monotonic pair is reported as malformed rather than as a wrapped size.
fn component_len(component: Component, start: u32, end: u32) -> Result<u32, Error> {
    let len = end.checked_sub(start).ok_or(Error::MalformedOffsets)?;
    if len > MAX_COOKIE_SIZE {
        return Err(Error::CookieTooLarge {
            component,
            size: len,
        });
    }
    Ok(len)
}

// Each table entry is 4 bytes; widen to u64 so the multiply cannot overflow,
// leaving only the usize narrowing to fail (16-bit targets).
fn table_len(count: u32) -> Result<usize, Error> {
    usize::try_from(u64::from(count) * 4).map_err(|_| Error::UnexpectedEof)
}

fn to_len(len: u32) -> Result<usize, Error> {
    usize::try_from(len).map_err(|_| Error::UnexpectedEof)
}

// rule 4: add the Mac-epoch padding in f64 first (Go's operand order), then
// saturating-cast — NaN → 0, ±Inf → i64::MIN/MAX — and clamp into the range
// `from_unix_timestamp` accepts. Weird timestamps neither panic nor error.
fn mac_epoch_time(mac_seconds: f64) -> OffsetDateTime {
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the saturating f64-to-i64 cast is the rule-4 contract"
    )]
    let unix = (mac_seconds + MAC_EPOCH_OFFSET) as i64;
    let clamped = unix.clamp(MIN_UNIX_TIMESTAMP, MAX_UNIX_TIMESTAMP);
    OffsetDateTime::from_unix_timestamp(clamped).unwrap_or(OffsetDateTime::UNIX_EPOCH)
}

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

// rule 5: drop a single trailing NUL if present; an empty field has no
// terminator to strip (Go's trimTerminator underflow guard).
fn trim_terminator(bytes: &[u8]) -> String {
    lossy(bytes.strip_suffix(&[0x00]).unwrap_or(bytes))
}

// rule 5: keep everything before the first NUL; without one, keep all bytes.
fn truncate_at_nul(bytes: &[u8]) -> String {
    lossy(bytes.split(|&byte| byte == 0x00).next().unwrap_or(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn component_len_rejects_non_monotonic_offsets() {
        assert!(matches!(
            component_len(Component::Domain, 10, 9),
            Err(Error::MalformedOffsets)
        ));
        assert!(matches!(component_len(Component::Name, 10, 10), Ok(0)));
        assert!(matches!(component_len(Component::Path, 10, 14), Ok(4)));
    }

    #[test]
    fn component_len_caps_at_4096() {
        assert!(matches!(
            component_len(Component::Comment, 0, 4096),
            Ok(4096)
        ));
        assert!(matches!(
            component_len(Component::Comment, 0, 4097),
            Err(Error::CookieTooLarge {
                component: Component::Comment,
                size: 4097
            })
        ));
    }

    #[test]
    fn mac_epoch_time_handles_extreme_values() {
        assert_eq!(mac_epoch_time(0.0).unix_timestamp(), 978_307_200);
        assert_eq!(mac_epoch_time(f64::NAN).unix_timestamp(), 0);
        assert_eq!(
            mac_epoch_time(f64::INFINITY).unix_timestamp(),
            MAX_UNIX_TIMESTAMP
        );
        assert_eq!(
            mac_epoch_time(f64::NEG_INFINITY).unix_timestamp(),
            MIN_UNIX_TIMESTAMP
        );
        assert_eq!(mac_epoch_time(1e300).unix_timestamp(), MAX_UNIX_TIMESTAMP);
    }

    #[test]
    fn string_truncation_policies_differ_per_field() {
        assert_eq!(trim_terminator(b"abc\x00"), "abc");
        assert_eq!(trim_terminator(b"abc\x00\x00"), "abc\x00");
        assert_eq!(trim_terminator(b"abc"), "abc");
        assert_eq!(trim_terminator(b""), "");

        assert_eq!(truncate_at_nul(b"abc\x00tail"), "abc");
        assert_eq!(truncate_at_nul(b"\x00tail"), "");
        assert_eq!(truncate_at_nul(b"abc"), "abc");
        assert_eq!(truncate_at_nul(b""), "");
    }

    #[test]
    fn lossy_replaces_invalid_utf8() {
        assert_eq!(lossy(&[0x61, 0xff, 0x62]), "a\u{fffd}b");
    }
}
