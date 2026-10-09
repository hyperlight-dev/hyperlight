// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Which scratch pages the guest wrote since the last restore.
//!
//! A restore zeroes scratch. Zeroing all of it costs time in its size,
//! however little the guest wrote, and mapping fresh memory instead
//! costs a fault on every page the guest then touches. Where the
//! hypervisor logs the guest's writes, a restore zeroes only the pages
//! in the log (see [`HostSharedMemory::zero_written`]).
//!
//! Tracking starts when scratch is mapped, before the guest runs, so
//! every restore, the first included, has the log. On MSHV the log is
//! not read until the first restore: until then every page reads as
//! written, so the guest sets up without tracking faults and the first
//! restore zeroes all of scratch, which MSHV holds resident anyway.
//!
//! On WHP, scratch is mapped with tracking, which costs the guest
//! nothing measurable, so the log is always used. Scratch is no longer
//! replaced on each restore, so the pages the guest writes stay
//! committed between restores, as all of scratch does on MSHV:
//! releasing them would cost a fault on each the next run touches.
//!
//! On MSHV, tracking is switched on for the whole VM. While it is on,
//! the guest's first write to each page after a read faults to the
//! hypervisor, and reading the log costs time in the size of scratch.
//! Measured on MSHV, that costs more than zeroing all of scratch when
//! scratch is under [`MIN_TRACKED_SCRATCH`], or when a run writes more
//! of it than [`writes_much`] allows. Small scratch is not tracked, and
//! tracking stops after such a run, until scratch is mapped again.
//!
//! [`HostSharedMemory::zero_written`]: crate::mem::shared_mem::HostSharedMemory::zero_written

use tracing::{debug, warn};

use crate::hypervisor::virtual_machine::{DirtyLog, DirtyTracking, HypervisorError};
use crate::mem::shared_mem::{DIRTY_PAGE_SIZE, DirtyRuns};

/// The smallest scratch tracked on MSHV. At 1 MiB, tracking a guest
/// that writes nothing costs as much as zeroing all of scratch; from 2
/// MiB on it costs less.
const MIN_TRACKED_SCRATCH: usize = 2 << 20;

/// Scratch from which zeroing all of it costs about three times more per
/// MiB on MSHV, so tracking pays off for runs that write more of it.
const LARGE_SCRATCH: usize = 32 << 20;

/// On MSHV, whether a run that wrote `written` of `pages` costs more
/// tracked than zeroing all of scratch would. Measured, tracking costs
/// more past about 5-10% of scratch written below [`LARGE_SCRATCH`] and
/// past about 25% from it on.
fn writes_much(written: usize, pages: usize) -> bool {
    let share = if pages * DIRTY_PAGE_SIZE < LARGE_SCRATCH {
        10
    } else {
        4
    };
    written * share > pages
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// Not tracking: scratch is reset in full.
    Off,
    /// Tracking since the last restore.
    On,
    /// The hypervisor failed; scratch is reset in full.
    Failed,
}

/// The guest's writes to scratch since the last restore, where the
/// hypervisor logs them. See the module docs.
#[derive(Debug)]
pub(crate) struct ScratchDirtyLog {
    state: State,
    /// The last log read, reused across restores where the hypervisor
    /// API fills a caller's buffer.
    bitmap: Vec<u64>,
    /// Tracking is switched on in the hypervisor.
    enabled: bool,
    /// No restore has read the log since scratch was mapped.
    since_mapped: bool,
}

impl Default for ScratchDirtyLog {
    fn default() -> Self {
        Self {
            state: State::Off,
            bitmap: Vec::new(),
            enabled: false,
            since_mapped: false,
        }
    }
}

impl ScratchDirtyLog {
    /// Scratch at `[gpa, gpa + size)` was just mapped, before the guest
    /// runs on it. Start tracking it where that pays off.
    pub(crate) fn mapped(&mut self, vm: &mut (impl DirtyLog + ?Sized), gpa: u64, size: usize) {
        if self.state == State::Failed {
            return;
        }
        self.since_mapped = true;
        let result = match vm.dirty_tracking() {
            DirtyTracking::Switched if size >= MIN_TRACKED_SCRATCH => {
                vm.enable_dirty_tracking().map(|()| self.enabled = true)
            }
            // Cleared now: the first restore zeroes only what was written
            // since, leaving the rest of scratch untouched (not resident).
            DirtyTracking::Mapped => vm.read_dirty_log(gpa, size, &mut self.bitmap),
            _ => {
                self.state = State::Off;
                return;
            }
        };
        self.state = match result {
            Ok(()) => State::On,
            Err(e) => self.fail(vm, gpa, size, e),
        };
    }

    /// Scratch at `[gpa, gpa + size)` is about to be unmapped. Tracking
    /// is switched off while the range is still mapped, since MSHV stops
    /// only once the bits of every page it read are set again.
    pub(crate) fn unmapping(&mut self, vm: &mut (impl DirtyLog + ?Sized), gpa: u64, size: usize) {
        if self.enabled {
            match vm.disable_dirty_tracking(gpa, size) {
                Ok(()) => self.enabled = false,
                Err(e) => self.state = failed(e),
            }
        }
        if self.state != State::Failed {
            self.state = State::Off;
        }
    }

    /// Called once per restore, before scratch at `[gpa, gpa + size)`
    /// is reset. Returns the pages the guest wrote since the last
    /// restore, one bit per page of [`DIRTY_PAGE_SIZE`], or `None` when
    /// they are not known and all of scratch must be reset. The log read
    /// is cleared: a restore that then fails leaves the sandbox
    /// unrecoverable, so nothing restores it on a log missing those pages.
    pub(crate) fn take(
        &mut self,
        vm: &mut (impl DirtyLog + ?Sized),
        gpa: u64,
        size: usize,
    ) -> Option<&mut Vec<u64>> {
        if self.state != State::On {
            return None;
        }
        if let Err(e) = vm.read_dirty_log(gpa, size, &mut self.bitmap) {
            self.state = self.fail(vm, gpa, size, e);
            return None;
        }
        // The first log after mapping holds what the guest wrote setting
        // up, before its first snapshot, which is not a run.
        let first = std::mem::take(&mut self.since_mapped);
        if vm.dirty_tracking() == DirtyTracking::Switched && !first {
            let pages = size / DIRTY_PAGE_SIZE;
            let written = written(&self.bitmap, pages);
            if writes_much(written, pages) {
                debug!("Scratch dirty tracking off: a run wrote {written} of {pages} pages");
                // The log just read is right either way.
                self.state = match vm.disable_dirty_tracking(gpa, size) {
                    Ok(()) => {
                        self.enabled = false;
                        State::Off
                    }
                    Err(e) => failed(e),
                };
            }
        }
        Some(&mut self.bitmap)
    }

    fn fail(
        &mut self,
        vm: &mut (impl DirtyLog + ?Sized),
        gpa: u64,
        size: usize,
        e: HypervisorError,
    ) -> State {
        // Best effort. Left on, tracking costs each page one fault at
        // most: pages fault only after a read clears them.
        if self.enabled && vm.disable_dirty_tracking(gpa, size).is_ok() {
            self.enabled = false;
        }
        failed(e)
    }
}

/// The log failed after `e`: scratch is reset in full from now on.
fn failed(e: HypervisorError) -> State {
    warn!("Scratch dirty log failed, restores zero all of scratch from now on: {e}");
    State::Failed
}

/// The set bits below `pages` in `bitmap`.
fn written(bitmap: &[u64], pages: usize) -> usize {
    DirtyRuns::new(bitmap, pages).map(|run| run.len()).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    const GPA: u64 = 0x1_0000_0000;
    const SIZE: usize = 16 << 20;
    const PAGES: usize = SIZE / DIRTY_PAGE_SIZE;

    /// A VM whose guest writes the first `written` pages between reads.
    #[derive(Debug, Default, PartialEq, Eq)]
    struct FakeVm {
        tracking: Option<DirtyTracking>,
        written: usize,
        fail: bool,
        enables: u32,
        disables: u32,
        reads: u32,
    }

    impl DirtyLog for FakeVm {
        fn dirty_tracking(&self) -> DirtyTracking {
            self.tracking.unwrap_or(DirtyTracking::None)
        }
        fn enable_dirty_tracking(&mut self) -> Result<(), HypervisorError> {
            self.enables += 1;
            Ok(())
        }
        fn disable_dirty_tracking(&mut self, _: u64, _: usize) -> Result<(), HypervisorError> {
            self.disables += 1;
            Ok(())
        }
        fn read_dirty_log(
            &mut self,
            gpa: u64,
            size: usize,
            bitmap: &mut Vec<u64>,
        ) -> Result<(), HypervisorError> {
            assert_eq!((gpa, size % DIRTY_PAGE_SIZE), (GPA, 0));
            if self.fail {
                return Err(HypervisorError::Injected);
            }
            self.reads += 1;
            *bitmap = vec![0; (size / DIRTY_PAGE_SIZE).div_ceil(64)];
            for page in 0..self.written {
                bitmap[page / 64] |= 1 << (page % 64);
            }
            Ok(())
        }
    }

    fn vm(tracking: DirtyTracking, written: usize) -> FakeVm {
        FakeVm {
            tracking: Some(tracking),
            written,
            ..FakeVm::default()
        }
    }

    fn restore(log: &mut ScratchDirtyLog, vm: &mut FakeVm) -> Option<usize> {
        log.take(vm, GPA, SIZE).map(|bitmap| written(bitmap, PAGES))
    }

    #[test]
    fn written_counts_only_pages_in_range() {
        assert_eq!(written(&[u64::MAX, u64::MAX], 70), 70);
        assert_eq!(written(&[0b1011], 3), 2);
        assert_eq!(written(&[], 10), 0);
    }

    #[test]
    fn untracked_vms_have_no_log() {
        let mut vm = vm(DirtyTracking::None, 1);
        let mut log = ScratchDirtyLog::default();
        log.mapped(&mut vm, GPA, SIZE);
        assert_eq!(restore(&mut log, &mut vm), None);
        assert_eq!((vm.enables, vm.disables, vm.reads), (0, 0, 0));
    }

    /// Read when mapped, so every restore, the first included, zeroes
    /// what the log says, whatever the guest writes.
    #[test]
    fn mapped_tracking_is_always_read() {
        let mut vm = vm(DirtyTracking::Mapped, PAGES / 2);
        let mut log = ScratchDirtyLog::default();
        log.mapped(&mut vm, GPA, SIZE);
        for _ in 0..10 {
            assert_eq!(restore(&mut log, &mut vm), Some(PAGES / 2));
        }
        assert_eq!((vm.enables, vm.disables, vm.reads), (0, 0, 11));
    }

    /// Enabled when mapped and not read: the first log reports every page
    /// (as the fake does by writing them all), later ones what was
    /// written.
    #[test]
    fn switched_tracking_starts_when_mapped() {
        let mut vm = vm(DirtyTracking::Switched, PAGES);
        let mut log = ScratchDirtyLog::default();
        log.mapped(&mut vm, GPA, SIZE);
        assert_eq!((vm.enables, vm.reads), (1, 0));
        assert_eq!(restore(&mut log, &mut vm), Some(PAGES));
        assert_eq!(vm.disables, 0);
        vm.written = 1;
        for _ in 0..1000 {
            assert_eq!(restore(&mut log, &mut vm), Some(1));
        }
        assert_eq!(vm.disables, 0);
    }

    #[test]
    fn small_scratch_is_not_tracked() {
        let size = MIN_TRACKED_SCRATCH - DIRTY_PAGE_SIZE;
        let mut vm = vm(DirtyTracking::Switched, 1);
        let mut log = ScratchDirtyLog::default();
        log.mapped(&mut vm, GPA, size);
        assert!(log.take(&mut vm, GPA, size).is_none());
        assert_eq!((vm.enables, vm.reads), (0, 0));
    }

    /// A run that writes much of scratch stops tracking for good, and
    /// its own log is still used. Setting up does not count.
    #[test]
    fn a_run_writing_much_stops_tracking() {
        let mut vm = vm(DirtyTracking::Switched, PAGES);
        let mut log = ScratchDirtyLog::default();
        log.mapped(&mut vm, GPA, SIZE);
        assert_eq!(restore(&mut log, &mut vm), Some(PAGES));
        assert_eq!(vm.disables, 0);
        vm.written = PAGES / 10 + 1;
        assert_eq!(restore(&mut log, &mut vm), Some(PAGES / 10 + 1));
        assert_eq!(vm.disables, 1);
        vm.written = 1;
        for _ in 0..10 {
            assert_eq!(restore(&mut log, &mut vm), None);
        }
        assert_eq!(vm.enables, 1);
    }

    #[test]
    fn larger_scratch_tolerates_more_writes() {
        let large = LARGE_SCRATCH / DIRTY_PAGE_SIZE;
        assert!(!writes_much(large / 4, large));
        assert!(writes_much(large / 4 + 1, large));
        assert!(!writes_much(PAGES / 10, PAGES));
        assert!(writes_much(PAGES / 10 + 1, PAGES));
    }

    /// Unmapping switches tracking off over the range still mapped, and
    /// the next mapping starts over, tracking again if it is large enough.
    #[test]
    fn remapping_stops_and_starts_over() {
        let mut vm = vm(DirtyTracking::Switched, 1);
        let mut log = ScratchDirtyLog::default();
        log.mapped(&mut vm, GPA, SIZE);
        restore(&mut log, &mut vm);
        log.unmapping(&mut vm, GPA, SIZE);
        assert_eq!(vm.disables, 1);
        log.mapped(&mut vm, GPA, MIN_TRACKED_SCRATCH - DIRTY_PAGE_SIZE);
        assert!(
            log.take(&mut vm, GPA, MIN_TRACKED_SCRATCH - DIRTY_PAGE_SIZE)
                .is_none()
        );
        log.unmapping(&mut vm, GPA, MIN_TRACKED_SCRATCH - DIRTY_PAGE_SIZE);
        assert_eq!(vm.disables, 1);
        log.mapped(&mut vm, GPA, SIZE);
        assert_eq!(restore(&mut log, &mut vm), Some(1));
        assert_eq!(restore(&mut log, &mut vm), Some(1));
        assert_eq!(vm.enables, 2);
    }

    /// A mapping that loses tracking has no log.
    #[test]
    fn a_mapping_without_tracking_has_no_log() {
        let mut vm = vm(DirtyTracking::Mapped, 1);
        let mut log = ScratchDirtyLog::default();
        log.mapped(&mut vm, GPA, SIZE);
        log.unmapping(&mut vm, GPA, SIZE);
        vm.tracking = Some(DirtyTracking::None);
        log.mapped(&mut vm, GPA, SIZE);
        assert!(log.take(&mut vm, GPA, SIZE).is_none());
    }

    #[test]
    fn a_failed_read_resets_in_full_from_then_on() {
        let mut vm = vm(DirtyTracking::Switched, 1);
        let mut log = ScratchDirtyLog::default();
        log.mapped(&mut vm, GPA, SIZE);
        vm.fail = true;
        assert_eq!(restore(&mut log, &mut vm), None);
        assert_eq!(vm.disables, 1);
        vm.fail = false;
        log.mapped(&mut vm, GPA, SIZE);
        for _ in 0..10 {
            assert_eq!(restore(&mut log, &mut vm), None);
        }
        assert_eq!((vm.enables, vm.reads), (1, 0));
    }
}
