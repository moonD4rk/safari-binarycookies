//! Convenience constructors reading from the filesystem or any reader.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::decode::from_bytes;
use crate::error::Error;
use crate::model::BinaryCookies;

/// Reads `reader` to the end and decodes the bytes with
/// [`from_bytes`](crate::from_bytes).
///
/// # Errors
///
/// Returns [`Error::Io`] when reading fails, otherwise any decode error from
/// [`from_bytes`](crate::from_bytes).
///
/// # Examples
///
/// ```no_run
/// let file = std::fs::File::open("Cookies.binarycookies")?;
/// let jar = safari_binarycookies::from_reader(file)?;
/// println!("{} pages", jar.pages.len());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub fn from_reader<R: Read>(mut reader: R) -> Result<BinaryCookies, Error> {
    let mut buffer = Vec::new();
    let _ = reader.read_to_end(&mut buffer)?;
    from_bytes(&buffer)
}

/// Opens the file at `path` and decodes it.
///
/// # Errors
///
/// Returns [`Error::Io`] when the file cannot be opened or read, otherwise any
/// decode error from [`from_bytes`](crate::from_bytes).
///
/// # Examples
///
/// ```no_run
/// let jar = safari_binarycookies::from_path("Cookies.binarycookies")?;
/// for cookie in jar.cookies() {
///     println!("{} = {}", cookie.name, cookie.value);
/// }
/// # Ok::<(), safari_binarycookies::Error>(())
/// ```
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub fn from_path<P: AsRef<Path>>(path: P) -> Result<BinaryCookies, Error> {
    let mut file = File::open(path)?;
    let cap = file
        .metadata()
        .ok()
        .and_then(|meta| usize::try_from(meta.len()).ok())
        .unwrap_or(0);
    let mut buffer = Vec::with_capacity(cap);
    let _ = file.read_to_end(&mut buffer)?;
    from_bytes(&buffer)
}
