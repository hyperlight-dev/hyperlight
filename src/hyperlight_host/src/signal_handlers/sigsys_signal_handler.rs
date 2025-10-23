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

extern "C-unwind" fn after_syscall_violation() {
    #[allow(clippy::panic)]
    std::panic::panic_any(crate::HyperlightError::DisallowedSyscall);
}

fn raw_format(prefix: &[u8], raw: usize) -> [u8; 64] {
    const PREFIX_BUF_LEN: usize = 64;
    const DIGITS_BUF_LEN: usize = 20;

    let mut buffer = [0u8; PREFIX_BUF_LEN];
    let mut i = prefix.len();

    // Copy the prefix message into the buffer.
    buffer[..i].copy_from_slice(prefix);

    // Format the number at the end of the buffer.
    let mut num = raw;
    let mut digits = [0u8; DIGITS_BUF_LEN];
    let mut j = 19;
    if num == 0 {
        digits[j] = b'0';
        j -= 1;
    } else {
        while num > 0 {
            digits[j] = b'0' + (num % 10) as u8;
            num /= 10;
            j -= 1;
        }
    }

    // Copy the number digits to the buffer after the prefix.
    let num_len = 19 - j;
    buffer[i..i + num_len].copy_from_slice(&digits[j + 1..20]);
    i += num_len;

    // Add a newline at the end.
    buffer[i] = b'\n';

    buffer
}
