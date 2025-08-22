/*
Copyright 2025  The Hyperlight Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

use core::fmt;
use core::result::Result;


/// FixedStringBuf is a buffer that can hold a fixed-size string of capacity N.
/// It is meant to be used with a slice that the user has pre-allocated
/// to avoid extra allocations during string formatting.
pub struct FixedStringBuf<const N: usize> {
    pub buf: [u8; N],
    pub pos: usize,
}

impl<'a, const N: usize> fmt::Write for FixedStringBuf<N> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        // we always reserve 1 byte for the null terminator, 
        // as the buffer must be convertible to CStr.
        let buf_end = self.buf.len() - 1;
        if self.pos + s.len() > buf_end {
            return Err(fmt::Error)
        }

        self.buf[self.pos..self.pos + s.len()].copy_from_slice(s.as_bytes());
        self.pos += s.len();
        Ok(())
    }
}

impl <const N: usize> FixedStringBuf<N> {
    pub fn as_str(&self) -> Result<&str, core::str::Utf8Error> {
        core::str::from_utf8(&self.buf[..self.pos])
    }

    pub const fn new() -> Self {
        return FixedStringBuf{
            buf: [0u8; N],
            pos: 0,
        }
    }

    /// Null terminates the underlying buffer,
    /// and converts to a CStr which borrows the underlying buffer's slice.
    pub fn as_c_str(&mut self) -> Result<&core::ffi::CStr, core::ffi::FromBytesUntilNulError> {
        // null terminate the buffer. 
        // we are guaranteed to have enough space since we always reserve one extra
        // byte for null in write_str, and assert buf.len() > 0 in the constructor.
        assert!(self.buf.len() > 0 && self.pos < self.buf.len());
        self.buf[self.pos] = 0;
        core::ffi::CStr::from_bytes_until_nul(&self.buf[..self.pos + 1])
    }
}


mod test {
    // disable unused import warnings
    #![allow(unused_imports)]
    use core::fmt::Write;
    use core::fmt;
    use super::FixedStringBuf;

    #[test]
    fn test_fixed_buf() {
        let mut buf = FixedStringBuf::<21>::new();

        assert_eq!(buf.as_str().unwrap(), "");

        write!(&mut buf, "{}", "0123456789").expect("Failed to write to FixedBuf");
        write!(&mut buf, "{}", "0123456789").expect("Failed to write to FixedBuf");
        assert_eq!(buf.as_str().unwrap(), "01234567890123456789");
        assert_eq!(buf.pos, 20);

        let res = write!(&mut buf, "10");
        assert_eq!(res, Err(fmt::Error));

        let c_str = buf.as_c_str().unwrap();
        assert_eq!(c_str.to_bytes(), b"01234567890123456789");
    }
}