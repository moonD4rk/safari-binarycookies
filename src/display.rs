//! Human-readable cookie formatting, mirroring the Go `Cookie.String()`.

use core::fmt;

use time::UtcOffset;

use crate::model::Cookie;

/// Formats as `<expires> <domain> <path> <name> <value>` followed by
/// ` Secure`, ` HttpOnly` and ` /* comment */` when present.
///
/// The timestamp is rendered as `YYYY-MM-DD HH:MM:SS`, always in UTC for
/// deterministic output (the Go reference renders in the value's own zone).
#[cfg_attr(docsrs, doc(cfg(feature = "display")))]
impl fmt::Display for Cookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Decoder output is always UTC; the checked conversion only matters
        // for caller-mutated timestamps, which must degrade, not panic.
        let utc = self
            .expires
            .checked_to_offset(UtcOffset::UTC)
            .unwrap_or(self.expires);
        // `{:04}` counts a minus sign against the width; Go pads the year to
        // four digits after the sign (-0028, not -028).
        let year = utc.year();
        if year < 0 {
            write!(f, "-{:04}", year.unsigned_abs())?;
        } else {
            write!(f, "{year:04}")?;
        }
        write!(
            f,
            "-{:02}-{:02} {:02}:{:02}:{:02} {} {} {} {}",
            u8::from(utc.month()),
            utc.day(),
            utc.hour(),
            utc.minute(),
            utc.second(),
            self.domain,
            self.path,
            self.name,
            self.value,
        )?;
        if self.is_secure() {
            f.write_str(" Secure")?;
        }
        if self.is_http_only() {
            f.write_str(" HttpOnly")?;
        }
        if let Some(comment) = self
            .comment
            .as_deref()
            .filter(|comment| !comment.is_empty())
        {
            write!(f, " /* {comment} */")?;
        }
        Ok(())
    }
}
