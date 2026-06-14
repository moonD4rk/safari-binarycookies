//! Bounds-checked byte cursor — the only place input bytes are sliced.

use crate::error::Error;

#[derive(Debug, Clone)]
pub(crate) struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub(crate) const fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).ok_or(Error::UnexpectedEof)?;
        let bytes = self.data.get(self.pos..end).ok_or(Error::UnexpectedEof)?;
        self.pos = end;
        Ok(bytes)
    }

    pub(crate) fn skip(&mut self, n: usize) -> Result<(), Error> {
        self.take(n).map(|_| ())
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::UnexpectedEof)
    }

    pub(crate) fn expect_tag<const N: usize>(
        &mut self,
        tag: [u8; N],
        err: Error,
    ) -> Result<(), Error> {
        if self.array::<N>()? == tag {
            Ok(())
        } else {
            Err(err)
        }
    }

    pub(crate) fn u32_be(&mut self) -> Result<u32, Error> {
        self.array().map(u32::from_be_bytes)
    }

    pub(crate) fn u32_le(&mut self) -> Result<u32, Error> {
        self.array().map(u32::from_le_bytes)
    }

    pub(crate) fn f64_le(&mut self) -> Result<f64, Error> {
        self.array().map(f64::from_le_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn take_advances_and_bounds_checks() {
        let mut cursor = Cursor::new(&[1, 2, 3]);
        assert!(matches!(cursor.take(2), Ok([1, 2])));
        assert_eq!(cursor.remaining(), 1);
        assert!(matches!(cursor.take(2), Err(Error::UnexpectedEof)));
        assert!(matches!(cursor.take(1), Ok([3])));
        assert!(matches!(cursor.take(1), Err(Error::UnexpectedEof)));
        assert!(matches!(cursor.take(0), Ok([])));
    }

    #[test]
    fn take_survives_usize_overflow() {
        let mut cursor = Cursor::new(&[0; 4]);
        assert!(matches!(cursor.skip(2), Ok(())));
        assert!(matches!(cursor.take(usize::MAX), Err(Error::UnexpectedEof)));
    }

    #[test]
    fn integer_reads_respect_endianness() {
        let mut cursor = Cursor::new(&[0x00, 0x00, 0x00, 0x0b, 0x0b, 0x00, 0x00, 0x00]);
        assert!(matches!(cursor.u32_be(), Ok(11)));
        assert!(matches!(cursor.u32_le(), Ok(11)));
        assert!(matches!(cursor.u32_le(), Err(Error::UnexpectedEof)));

        let float_bytes = 1.5f64.to_le_bytes();
        let mut cursor = Cursor::new(&float_bytes);
        assert!(matches!(cursor.f64_le(), Ok(v) if v.to_bits() == 1.5f64.to_bits()));
    }
}
