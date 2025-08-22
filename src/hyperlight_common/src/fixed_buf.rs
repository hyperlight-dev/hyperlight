use core::fmt;
use core::result::Result;
use core::ffi::{CStr, FromBytesUntilNulError};

pub struct FixedStringBuf<'a> {
    pub buf: &'a mut [u8],
    pub pos: usize,
}

impl<'a> fmt::Write for FixedStringBuf<'a> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        // we always reserve 1 byte for the null terminator, 
        // as the buffer must be convertible to a CStr.
        let buf_end = self.buf.len() - 1;
        if self.pos + s.len() > buf_end {
            return Err(fmt::Error)
        }

        self.buf[self.pos..self.pos + s.len()].copy_from_slice(s.as_bytes());
        self.pos += s.len();
        Ok(())
    }
}

impl <'a> FixedStringBuf<'a> {
    pub fn as_str(&self) -> Result<&str, core::str::Utf8Error> {
        core::str::from_utf8(&self.buf[..self.pos])
    }

    pub fn new(buf: &'a mut [u8]) -> FixedStringBuf<'a> {
        assert!(buf.len() > 0);
        FixedStringBuf {
            buf,
            pos: 0,
        }
    }

    pub fn as_c_str(&mut self) -> Result<&CStr, FromBytesUntilNulError> {
        // null terminate buffer. 
        // we are guaranteed to have enough space since we always reserve one extra
        // byte for null in write_str
        self.buf[self.pos] = 0;
        CStr::from_bytes_until_nul(&self.buf[..self.pos + 1])
    }
}

mod test {
    use super::{FixedStringBuf};
    use core::fmt::Write;
    use core::fmt;
    #[test]
    fn test_fixed_buf() {
        let mut bs = [0; 21];
        let mut buf = FixedStringBuf::new(&mut bs);
        write!(&mut buf, "{}", "0123456789").expect("Failed to write to FixedBuf");
        write!(&mut buf, "{}", "0123456789").expect("Failed to write to FixedBuf");
        assert_eq!(buf.as_str().unwrap(), "01234567890123456789");
        assert_eq!(buf.pos, 20);

        let res = write!(&mut buf, "10");
        assert_eq!(res, Err(fmt::Error));
    }
}