#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod cursor;
mod decode;
mod error;
mod iter;
mod model;

#[cfg(feature = "display")]
mod display;
#[cfg(feature = "std")]
mod read;

pub use decode::from_bytes;
pub use error::{Component, Error};
pub use iter::{Cookies, cookies};
pub use model::{BinaryCookies, Cookie, CookieIter, Flags, Page};
#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub use read::{from_path, from_reader};
// `Cookie.expires`/`Cookie.creation` hold this type, so re-export it: callers
// can name it without depending on `time` at a matching version themselves.
#[doc(no_inline)]
pub use time::OffsetDateTime;
