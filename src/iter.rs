//! Lazy cookie stream over a `.binarycookies` buffer.

use core::fmt;
use core::iter::FusedIterator;

use crate::decode::Decoder;
use crate::error::Error;
use crate::model::Cookie;

/// Returns a lazy iterator over every cookie in `input`, flattening the page
/// layer.
///
/// The file header (magic, page count, page-size table) is validated eagerly;
/// pages and cookies are then parsed on demand. On input that decodes fully,
/// the iterator yields exactly the cookies of
/// [`from_bytes`](crate::from_bytes), in order. On malformed input it yields
/// the cookies parsed before the first structural violation, then that error
/// once, then fuses — whereas [`from_bytes`](crate::from_bytes) returns only
/// the error.
///
/// # Errors
///
/// Returns an error when the magic is wrong, the page count exceeds the
/// hardening cap, or the header is truncated.
///
/// # Examples
///
/// ```
/// // A minimal file: `cook` magic + zero pages + 8-byte checksum.
/// let data = *b"cook\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
/// let mut cookies = safari_binarycookies::cookies(&data)?;
/// assert!(cookies.next().is_none());
/// # Ok::<(), safari_binarycookies::Error>(())
/// ```
pub fn cookies(input: &[u8]) -> Result<Cookies<'_>, Error> {
    let mut decoder = Decoder::new(input);
    decoder.signature()?;
    let pages_left = decoder.page_count()?;
    decoder.skip_page_size_table(pages_left)?;
    Ok(Cookies {
        decoder,
        pages_left,
        left_in_page: 0,
        finished: false,
    })
}

/// Lazy iterator returned by [`cookies`].
///
/// Yields `Result<Cookie, Error>` and fuses after the first error or the end
/// of the last page. Cloning is cheap and restarts nothing: a clone resumes
/// from the current position.
#[derive(Clone)]
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct Cookies<'a> {
    decoder: Decoder<'a>,
    pages_left: u32,
    left_in_page: u32,
    finished: bool,
}

impl Cookies<'_> {
    fn read_page_header(&mut self) -> Result<u32, Error> {
        self.decoder.page_tag()?;
        let count = self.decoder.cookie_count()?;
        self.decoder.skip_cookie_offset_table(count)?;
        self.decoder.page_end()?;
        Ok(count)
    }
}

impl Iterator for Cookies<'_> {
    type Item = Result<Cookie, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        loop {
            if self.left_in_page > 0 {
                self.left_in_page -= 1;
                let result = self.decoder.cookie();
                if result.is_err() {
                    self.finished = true;
                }
                return Some(result);
            }
            if self.pages_left > 0 {
                self.pages_left -= 1;
                match self.read_page_header() {
                    Ok(count) => self.left_in_page = count,
                    Err(error) => {
                        self.finished = true;
                        return Some(Err(error));
                    }
                }
                continue;
            }
            self.finished = true;
            // Mirror the eager decoder, which reads the 8-byte checksum after
            // the last page, so both paths fail alike on a truncated trailer.
            return match self.decoder.checksum() {
                Ok(_) => None,
                Err(error) => Some(Err(error)),
            };
        }
    }

    // Remaining yields are unknowable up front (a parse error both adds an
    // item and ends the stream), so only the fused empty state is exact.
    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.finished {
            (0, Some(0))
        } else {
            (0, None)
        }
    }
}

impl FusedIterator for Cookies<'_> {}

impl fmt::Debug for Cookies<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cookies")
            .field("pages_left", &self.pages_left)
            .field("left_in_page", &self.left_in_page)
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}
