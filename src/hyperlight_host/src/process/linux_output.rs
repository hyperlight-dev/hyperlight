// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, PipeReader, PipeWriter, Read};
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::Mutex;
use std::thread::JoinHandle;

use crate::{Result, new_error};

const TAIL_BYTES: usize = 64 * 1024;

struct Drain {
    cancellation: PipeWriter,
    thread: JoinHandle<io::Result<(Vec<u8>, u64, bool)>>,
}

pub(super) struct Output {
    name: String,
    drain: Mutex<Option<Drain>>,
}

impl Output {
    pub(super) fn new(name: &str) -> Result<(Self, File)> {
        let (reader, writer) = io::pipe()?;
        let (cancel_reader, cancellation) = io::pipe()?;
        // SAFETY: reader owns a live descriptor. F_GETFL takes no third argument.
        let flags = unsafe { libc::fcntl(reader.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error().into());
        }
        // SAFETY: the descriptor is live and F_SETFL accepts these status flags.
        if unsafe { libc::fcntl(reader.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error().into());
        }
        let thread = std::thread::Builder::new()
            .name("hyperlight-process-output".to_owned())
            .spawn(move || drain(reader, cancel_reader))?;
        Ok((
            Self {
                name: name.to_owned(),
                drain: Mutex::new(Some(Drain {
                    cancellation,
                    thread,
                })),
            },
            File::from(OwnedFd::from(writer)),
        ))
    }

    pub(super) fn finish(&self) -> Result<()> {
        let Some(drain) = self
            .drain
            .lock()
            .map_err(|_| new_error!("Process output state is poisoned"))?
            .take()
        else {
            return Ok(());
        };
        drop(drain.cancellation);
        let (tail, discarded, cut_off) = drain
            .thread
            .join()
            .map_err(|_| new_error!("Process output reader panicked"))??;
        if !tail.is_empty() || discarded != 0 {
            tracing::debug!(
                process = self.name,
                discarded_bytes = discarded,
                cut_off,
                output = ?String::from_utf8_lossy(&tail),
                "Process diagnostic tail"
            );
        }
        Ok(())
    }
}

impl Drop for Output {
    fn drop(&mut self) {
        if let Err(error) = self.finish() {
            tracing::error!(?error, process = self.name, "Process output cleanup failed");
        }
    }
}

fn drain(mut reader: PipeReader, cancellation: PipeReader) -> io::Result<(Vec<u8>, u64, bool)> {
    let mut descriptors = [
        libc::pollfd {
            fd: reader.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: cancellation.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    let mut tail = VecDeque::with_capacity(TAIL_BYTES);
    let mut discarded = 0;
    let mut buffer = [0; 4096];
    let mut closing_budget = TAIL_BYTES;
    let mut cut_off = false;
    loop {
        // SAFETY: descriptors holds two initialized pollfd values with live owners.
        if unsafe { libc::poll(descriptors.as_mut_ptr(), 2, -1) } < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        let cancelled = descriptors[1].revents != 0;
        if cancelled && closing_budget == 0 {
            cut_off = true;
            break;
        }
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                let overflow = (tail.len() + count).saturating_sub(TAIL_BYTES);
                tail.drain(..overflow);
                discarded += overflow as u64;
                tail.extend(&buffer[..count]);
                if cancelled {
                    closing_budget = closing_budget.saturating_sub(count);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock && cancelled => break,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
    }
    Ok((tail.into_iter().collect(), discarded, cut_off))
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    #[test]
    fn output_is_write_only_and_cleanup_does_not_need_writer_eof() {
        let (output, writer) = Output::new("fixture").unwrap();
        // SAFETY: writer owns this live descriptor. F_GETFL reads status flags.
        let flags = unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_GETFL) };
        assert_eq!(flags & libc::O_ACCMODE, libc::O_WRONLY);
        output.finish().unwrap();
        output.finish().unwrap();
        drop(writer);
    }

    #[test]
    fn output_drains_beyond_pipe_capacity() {
        let (output, mut writer) = Output::new("fixture").unwrap();
        writer.write_all(&vec![b'x'; TAIL_BYTES * 4]).unwrap();
        drop(writer);
        output.finish().unwrap();
    }
}
