// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Resetting a sandbox's scratch region to zeros on restore, on KVM.
//!
//! Dropping a page (`MADV_DONTNEED`) makes the guest's next touch of it
//! fault twice, in the host for a zeroed page and in KVM to map it, which
//! costs a few microseconds a page on a nested hypervisor. Zeroing in
//! place the pages a run wrote keeps them mapped, which costs a fraction
//! of that, so every reset zeroes those and keeps them.
//!
//! `/proc/self/pagemap` reports each page's page-table entry, and every
//! reset reads it for the whole region. A page with memory of its own
//! that holds data is zeroed and kept. One that holds only zeros is kept
//! as it is: it may be one the last run wrote zeros to, which a drop would
//! make the next run fault on again. Every [`GIVE_BACK_EVERY`] resets,
//! pages holding only zeros are dropped instead, up to [`MAX_DROPS`] runs
//! of them, so memory a run once used is given back without a guest that
//! writes zeros faulting on every run. A page in swap, or mapped to
//! memory it shares that holds data (a page shared with a forked child),
//! is dropped. One that shares only zeros (the zero page a read maps)
//! holds no data, and is left like an unwritten page of its own. A page
//! with an empty entry reads as zero and is left alone. The kernel reports
//! any page that holds data as present or swapped, so this leaves no data
//! behind. Pagemap is opened once per process (and once per sandbox in a
//! forked child), and used only after it reports a page the process
//! wrote.
//!
//! From Linux 6.7, the `PAGEMAP_SCAN` ioctl reports pagemap as ranges of
//! pages alike, skipping what was never touched, so a reset costs time
//! in what scratch holds rather than in its size. It does not tell a page
//! shared with a forked child from one of our own: one holding data is
//! zeroed then, which copies it first, as safe as dropping it. Where the
//! ioctl fails (an older kernel, a filter), entries are read one a page.

use std::fs::File;
use std::ops::Range;
use std::os::unix::fs::FileExt;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

use tracing::{debug, warn};

use super::shared_mem::{ExclusiveSharedMemory, SharedMemory};

/// The most separate drops of each kind a reset makes. A guest that
/// scatters shared pages so a reset would drop them one by one has the
/// whole region dropped instead. Runs of pages holding only zeros past
/// it stay, for a later reset that gives them back.
const MAX_DROPS: usize = 64;

/// How often a reset gives back the pages holding only zeros. A page
/// dropped costs a fault when the guest next touches it, which costs
/// about as much as checking it for data on 16 resets.
const GIVE_BACK_EVERY: usize = 16;

/// Pagemap entries read at once.
const CHUNK_PAGES: usize = 512;

/// Ranges one `PAGEMAP_SCAN` call reports.
const SCAN_RANGES: usize = 256;

/// `PAGEMAP_SCAN` failed in this process, so resets read entries one a
/// page. Whether it works is the kernel's, not a sandbox's.
static NO_RANGES: AtomicBool = AtomicBool::new(false);

const PM_PRESENT: u64 = 1 << 63;
const PM_SWAPPED: u64 = 1 << 62;
const PM_EXCLUSIVE: u64 = 1 << 56;

/// The process's pagemap, with the process that opened it, set once and
/// never freed. A forked child inherits its parent's, which shows the
/// parent's pages. Published with an atomic rather than a lock, which a
/// fork could leave held.
static PAGEMAP: AtomicPtr<(u32, Pagemap)> = AtomicPtr::new(std::ptr::null_mut());

/// The process's pagemap, once a reset opened it.
fn process_pagemap() -> Option<&'static (u32, Pagemap)> {
    // SAFETY: set only from a leaked `Box`, never freed or changed after.
    unsafe { PAGEMAP.load(Ordering::Acquire).as_ref() }
}

/// That pagemap is unusable was logged.
static WARNED: AtomicBool = AtomicBool::new(false);

/// How a scratch region is reset in place. See the module docs.
#[derive(Debug, Default)]
pub(crate) struct ScratchReset {
    /// Resets since pages holding only zeros were last given back.
    resets: usize,
    /// The pagemap of a forked child, with the child.
    forked: Option<(u32, Pagemap)>,
    /// The process for which pagemap could not be opened, so it is not
    /// tried again.
    unusable: Option<u32>,
    /// Read entries one a page, to test that.
    #[cfg(test)]
    no_ranges: bool,
    /// The last scan read ranges.
    #[cfg(test)]
    read_ranges: bool,
    /// Pagemap fails, to test that.
    #[cfg(test)]
    fail_pagemap: bool,
}

/// This process's `/proc/self/pagemap`.
#[derive(Debug)]
struct Pagemap {
    file: File,
}

impl Pagemap {
    /// Open pagemap, and check that it reports a page this process wrote
    /// as present and its own. Pagemap that cannot see that (an
    /// emulated `/proc`, say) is not used. A fork in between shares the
    /// page again, so the check is tried a few times.
    fn open() -> std::io::Result<Self> {
        let pagemap = Self {
            file: File::open("/proc/self/pagemap")?,
        };
        let mut probe = Box::new(0u64);
        for _ in 0..3 {
            // SAFETY: a valid, aligned `u64` of our own. Volatile, so
            // the write that backs the page happens.
            unsafe { std::ptr::write_volatile(&mut *probe, 1) };
            let mut entry = [0u64];
            pagemap.read(&*probe as *const u64 as usize, &mut entry)?;
            if kept(entry[0]) {
                return Ok(pagemap);
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "pagemap does not report this process's pages",
        ))
    }

    /// Read the entries of the pages from `addr` on into `entries`, at
    /// most [`CHUNK_PAGES`].
    fn read(&self, addr: usize, entries: &mut [u64]) -> std::io::Result<()> {
        // SAFETY: the bytes of `entries`, which any bit pattern fills.
        let bytes = unsafe {
            std::slice::from_raw_parts_mut(entries.as_mut_ptr().cast::<u8>(), entries.len() * 8)
        };
        let offset = (addr / page_size::get()) as u64 * 8;
        self.file.read_exact_at(bytes, offset)
    }
}

/// [`Pagemap::open`], saying once per process when it fails.
fn open_warned() -> std::io::Result<Pagemap> {
    Pagemap::open().inspect_err(|e| {
        if !WARNED.swap(true, Ordering::Relaxed) {
            warn!("scratch is dropped on restore while pagemap is unusable: {e}");
        }
    })
}

/// Backed by memory of its own: zero it and keep it.
fn kept(entry: u64) -> bool {
    entry & (PM_PRESENT | PM_EXCLUSIVE) == PM_PRESENT | PM_EXCLUSIVE
}

/// Backed: present, or in swap.
#[cfg(test)]
fn held(entry: u64) -> bool {
    entry & (PM_PRESENT | PM_SWAPPED) != 0
}

/// The region a reset works on, borrowed exclusively.
struct Region<'a> {
    mem: &'a mut ExclusiveSharedMemory,
    pages: usize,
}

impl Region<'_> {
    fn addr(&self, page: usize) -> usize {
        self.mem.base_ptr() as usize + page * page_size::get()
    }

    /// Drop `pages`. They read as zero and refill on demand.
    fn drop_pages(&mut self, pages: Range<usize>) -> std::io::Result<()> {
        assert!(pages.start <= pages.end && pages.end <= self.pages);
        if pages.is_empty() {
            return Ok(());
        }
        // SAFETY: the pages lie in the region, a private anonymous
        // mapping borrowed exclusively.
        let ret = unsafe {
            libc::madvise(
                self.addr(pages.start) as *mut libc::c_void,
                pages.len() * page_size::get(),
                libc::MADV_DONTNEED,
            )
        };
        if ret == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    /// Holds only zeros. Stops at the first word that is not, checking
    /// the last first, where data often sits (a stack grows down from the
    /// end of its page).
    fn is_zero(&mut self, page: usize) -> bool {
        let size = page_size::get();
        let bytes = &self.mem.as_mut_slice()[page * size..(page + 1) * size];
        // SAFETY: any bytes are valid `u64`s; the aligned middle is
        // checked as words, the rest as bytes.
        let (head, words, tail) = unsafe { bytes.align_to::<u64>() };
        words.last().is_none_or(|&w| w == 0)
            && head.iter().all(|&b| b == 0)
            && tail.iter().all(|&b| b == 0)
            && words.iter().all(|&w| w == 0)
    }

    fn zero_pages(&mut self, pages: Range<usize>) {
        let page = page_size::get();
        self.mem.as_mut_slice()[pages.start * page..pages.end * page].fill(0);
    }
}

impl ScratchReset {
    /// Reset `mem` to zeros, keeping mapped the pages that are its own,
    /// as the module docs say. On an error the region may be partly
    /// reset, and the caller must reset it some other way.
    pub(crate) fn reset(&mut self, mem: &mut ExclusiveSharedMemory) -> std::io::Result<()> {
        let pages = mem.mem_size() / page_size::get();
        let mut region = Region { mem, pages };
        self.resets += 1;
        let give_back = self.resets == GIVE_BACK_EVERY;
        if give_back {
            self.resets = 0;
        }
        if self.scan(&mut region, give_back)? > MAX_DROPS {
            region.drop_pages(0..pages)?;
        }
        Ok(())
    }

    /// This process's pagemap. Where it cannot be opened, this sandbox
    /// does not try again.
    fn pagemap(&mut self) -> std::io::Result<&Pagemap> {
        let pid = std::process::id();
        if self.unusable == Some(pid) {
            return Err(std::io::ErrorKind::Unsupported.into());
        }
        if let Err(e) = self.open_pagemap(pid) {
            self.unusable = Some(pid);
            return Err(e);
        }
        match process_pagemap() {
            Some((opener, pagemap)) if *opener == pid => Ok(pagemap),
            _ => self
                .forked
                .as_ref()
                .map(|(_, pagemap)| pagemap)
                .ok_or_else(|| std::io::ErrorKind::Unsupported.into()),
        }
    }

    /// Open the pagemap of process `pid` if it is not open: the process's
    /// own, or in a forked child, the child's.
    fn open_pagemap(&mut self, pid: u32) -> std::io::Result<()> {
        #[cfg(test)]
        if self.fail_pagemap {
            return Err(std::io::ErrorKind::Unsupported.into());
        }
        if process_pagemap().is_none() {
            let opened = Box::into_raw(Box::new((pid, open_warned()?)));
            // Another thread may set it first; either is this process's.
            if PAGEMAP
                .compare_exchange(
                    std::ptr::null_mut(),
                    opened,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
            {
                // SAFETY: from `Box::into_raw` above, and not published.
                drop(unsafe { Box::from_raw(opened) });
            }
        }
        let own = matches!(process_pagemap(), Some((opener, _)) if *opener == pid);
        if !own && !matches!(&self.forked, Some((child, _)) if *child == pid) {
            self.forked = Some((pid, open_warned()?));
        }
        Ok(())
    }

    /// Zero the pages with memory of their own that hold data, and drop
    /// the rest that hold data, one drop per run between kept pages (see
    /// [`Run::end`]), and with `give_back` those holding only zeros too.
    /// Returns the drops of runs that had to go, and stops past
    /// [`MAX_DROPS`] of them for the caller to drop it all.
    fn scan(&mut self, region: &mut Region<'_>, give_back: bool) -> std::io::Result<usize> {
        #[cfg(test)]
        let ranges = !self.no_ranges;
        #[cfg(not(test))]
        let ranges = true;
        if ranges
            && !NO_RANGES.load(Ordering::Relaxed)
            && let Some(drops) = self.scan_ranges(region, give_back)?
        {
            #[cfg(test)]
            {
                self.read_ranges = true;
            }
            return Ok(drops);
        }
        self.scan_entries(region, give_back)
    }

    /// [`scan`](Self::scan) from pagemap entries, one a page.
    fn scan_entries(&mut self, region: &mut Region<'_>, give_back: bool) -> std::io::Result<usize> {
        let mut walk = Walk::new(give_back);
        let mut entries = [0u64; CHUNK_PAGES];
        let pagemap = self.pagemap()?;
        let mut chunk = 0;
        while chunk < region.pages {
            let n = CHUNK_PAGES.min(region.pages - chunk);
            pagemap.read(region.addr(chunk), &mut entries[..n])?;
            for (i, &entry) in entries[..n].iter().enumerate() {
                let page = chunk + i;
                let own = kept(entry);
                let present = entry & PM_PRESENT != 0;
                let zero = present && region.is_zero(page);
                // A shared page holding only zeros (the zero page a read
                // maps) holds no data; one holding data, or a page in
                // swap, must go.
                let shared = !own && (entry & PM_SWAPPED != 0 || present && !zero);
                if walk.page(region, page, own && !zero, shared, present && zero)? {
                    return Ok(walk.drops.shared);
                }
            }
            chunk += n;
        }
        walk.finish(region)
    }

    /// [`scan`](Self::scan) from `PAGEMAP_SCAN`'s ranges of present or
    /// swapped pages; what lies between them is empty. `None` when the
    /// first call fails, before anything is reset, for the caller to read
    /// entries instead. A later call failing is an error, as the region is
    /// partly reset. Either way, later scans read entries.
    fn scan_ranges(
        &mut self,
        region: &mut Region<'_>,
        give_back: bool,
    ) -> std::io::Result<Option<usize>> {
        let size = page_size::get();
        let base = region.addr(0) as u64;
        let pagemap = self.pagemap()?;
        let mut ranges = [PageRegion::default(); SCAN_RANGES];
        let mut arg = PmScanArg::new(base, base + (region.pages * size) as u64);
        let mut walk = Walk::new(give_back);
        let mut next = 0;
        loop {
            let n = match pagemap_scan(&pagemap.file, &mut arg, &mut ranges) {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    // Before Linux 6.7 there is no such ioctl; anything else
                    // is unexpected.
                    if e.raw_os_error() == Some(libc::ENOTTY) {
                        debug!("no PAGEMAP_SCAN, reading pagemap one entry a page");
                    } else {
                        warn!("PAGEMAP_SCAN failed, reading pagemap one entry a page: {e}");
                    }
                    NO_RANGES.store(true, Ordering::Relaxed);
                    // Past the first call, part of the region is reset: the
                    // caller drops it all.
                    return if arg.start == base { Ok(None) } else { Err(e) };
                }
            };
            for range in ranges.iter().take(n) {
                let first = (range.start - base) as usize / size;
                let end = (range.end - base) as usize / size;
                if first > next && walk.page(region, next, false, false, false)? {
                    return Ok(Some(walk.drops.shared));
                }
                let swapped = range.categories & PAGE_IS_SWAPPED != 0;
                let zero_page = range.categories & PAGE_IS_PFNZERO != 0;
                for page in first..end {
                    let zero = !swapped && (zero_page || region.is_zero(page));
                    if walk.page(region, page, !swapped && !zero, swapped, zero)? {
                        return Ok(Some(walk.drops.shared));
                    }
                }
                next = end;
            }
            if arg.walk_end >= arg.end {
                break;
            }
            arg.start = arg.walk_end;
        }
        if next < region.pages && walk.page(region, next, false, false, false)? {
            return Ok(Some(walk.drops.shared));
        }
        walk.finish(region).map(Some)
    }
}

/// Run `PAGEMAP_SCAN` on `pagemap` into `ranges`. Returns the ranges it
/// filled.
fn pagemap_scan(
    pagemap: &File,
    arg: &mut PmScanArg,
    ranges: &mut [PageRegion],
) -> std::io::Result<usize> {
    use std::os::fd::AsRawFd;
    arg.vec = ranges.as_mut_ptr() as u64;
    arg.vec_len = ranges.len() as u64;
    // SAFETY: `arg` points at `ranges`, borrowed for the call, which the
    // kernel fills with at most `vec_len` entries. The kernel writes no
    // other memory of ours but `arg`.
    let n = unsafe { libc::ioctl(pagemap.as_raw_fd(), PAGEMAP_SCAN, &mut *arg) };
    usize::try_from(n).map_err(|_| std::io::Error::last_os_error())
}

/// `PAGEMAP_SCAN`: `_IOWR('f', 16, struct pm_scan_arg)`. The request is
/// a `c_ulong` on glibc and a `c_int` on musl.
const PAGEMAP_SCAN: libc::Ioctl = 0xC060_6610u32 as libc::Ioctl;
const PAGE_IS_PRESENT: u64 = 1 << 3;
const PAGE_IS_SWAPPED: u64 = 1 << 4;
const PAGE_IS_PFNZERO: u64 = 1 << 5;

/// `struct pm_scan_arg`.
#[repr(C)]
#[derive(Default)]
struct PmScanArg {
    size: u64,
    flags: u64,
    start: u64,
    end: u64,
    walk_end: u64,
    vec: u64,
    vec_len: u64,
    max_pages: u64,
    category_inverted: u64,
    category_mask: u64,
    category_anyof_mask: u64,
    return_mask: u64,
}

impl PmScanArg {
    /// Report the present or swapped pages in `[start, end)`, flagging
    /// those mapped to the zero page. [`pagemap_scan`] says where.
    fn new(start: u64, end: u64) -> Self {
        Self {
            size: size_of::<Self>() as u64,
            start,
            end,
            category_anyof_mask: PAGE_IS_PRESENT | PAGE_IS_SWAPPED,
            return_mask: PAGE_IS_PRESENT | PAGE_IS_SWAPPED | PAGE_IS_PFNZERO,
            ..Self::default()
        }
    }
}

/// `struct page_region`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct PageRegion {
    start: u64,
    end: u64,
    categories: u64,
}

/// The runs a scan makes from pages fed in order.
struct Walk {
    run: Run,
    drops: Drops,
}

impl Walk {
    /// With `give_back`, runs holding only zeros are dropped.
    fn new(give_back: bool) -> Self {
        Self {
            run: Run {
                start: 0,
                keep: false,
                shared: false,
                zero: false,
            },
            drops: Drops {
                give_back,
                ..Drops::default()
            },
        }
    }

    /// Page `page` is kept, or not and holds shared or swapped data, or
    /// zeros. Every page up to the next one fed is as this one. True once
    /// shared drops pass [`MAX_DROPS`].
    fn page(
        &mut self,
        region: &mut Region<'_>,
        page: usize,
        keep: bool,
        shared: bool,
        zero: bool,
    ) -> std::io::Result<bool> {
        if keep != self.run.keep {
            if self.run.end(region, page, &mut self.drops)? {
                return Ok(true);
            }
            self.run = Run {
                start: page,
                keep,
                shared: false,
                zero: false,
            };
        }
        self.run.shared |= shared;
        self.run.zero |= zero;
        Ok(false)
    }

    /// End the last run at the end of the region.
    fn finish(mut self, region: &mut Region<'_>) -> std::io::Result<usize> {
        self.run.end(region, region.pages, &mut self.drops)?;
        Ok(self.drops.shared)
    }
}

/// Drops made by a reset.
#[derive(Default)]
struct Drops {
    /// Of runs holding shared or swapped pages, which must go.
    shared: usize,
    /// Of runs holding only zeros, dropped to give their memory back.
    zero: usize,
    /// Runs holding only zeros are dropped.
    give_back: bool,
}

/// A run of pages kept, or not, between pages that are the other.
struct Run {
    start: usize,
    keep: bool,
    shared: bool,
    zero: bool,
}

impl Run {
    /// Zero the run if kept. Otherwise drop it, empty entries and all,
    /// so the guest cannot make a reset drop page by page: always when it
    /// holds shared or swapped pages, and when it holds pages holding only
    /// zeros on a reset that gives them back, up to [`MAX_DROPS`] of those;
    /// past that they stay, zero.
    /// True once shared drops pass [`MAX_DROPS`].
    fn end(&self, region: &mut Region<'_>, end: usize, drops: &mut Drops) -> std::io::Result<bool> {
        let pages = self.start..end;
        if self.keep {
            region.zero_pages(pages);
        } else if self.shared {
            region.drop_pages(pages)?;
            drops.shared += 1;
        } else if self.zero && drops.give_back && drops.zero < MAX_DROPS {
            region.drop_pages(pages)?;
            drops.zero += 1;
        }
        Ok(drops.shared > MAX_DROPS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page() -> usize {
        page_size::get()
    }

    /// Backed 4 KiB at a time, as KVM scratch is, whatever the host's
    /// hypervisor.
    fn region(pages: usize) -> ExclusiveSharedMemory {
        let mem = ExclusiveSharedMemory::new(pages * page()).unwrap();
        // SAFETY: the test's own mapping.
        unsafe {
            libc::madvise(
                mem.base_ptr() as *mut libc::c_void,
                mem.mem_size(),
                libc::MADV_NOHUGEPAGE,
            )
        };
        mem
    }

    fn write(mem: &mut ExclusiveSharedMemory, page_index: usize, byte: u8) {
        mem.as_mut_slice()[page_index * page() + 7] = byte;
    }

    fn entry(mem: &ExclusiveSharedMemory, page_index: usize) -> u64 {
        let pagemap = Pagemap {
            file: File::open("/proc/self/pagemap").unwrap(),
        };
        let mut e = [0u64];
        pagemap
            .read(mem.base_ptr() as usize + page_index * page(), &mut e)
            .unwrap();
        e[0]
    }

    /// Reading maps the zero page on dropped pages, which a reset that
    /// gives back drops again.
    fn all_zero(mem: &mut ExclusiveSharedMemory) -> bool {
        mem.as_mut_slice().iter().all(|b| *b == 0)
    }

    fn reset(state: &mut ScratchReset, mem: &mut ExclusiveSharedMemory) {
        state.reset(mem).unwrap();
    }

    /// A reset that gives back the pages holding only zeros.
    fn give_back(state: &mut ScratchReset, mem: &mut ExclusiveSharedMemory) {
        state.resets = GIVE_BACK_EVERY - 1;
        reset(state, mem);
        assert_eq!(state.resets, 0);
    }

    /// Every reset leaves the region zero, whatever the run wrote: the
    /// usual pages, others far away, and nothing at all.
    #[test]
    fn every_reset_leaves_the_region_zero() {
        for mut state in states() {
            let mut mem = region(2048);
            for round in 0..100usize {
                match round % 7 {
                    3 => {}
                    5 => {
                        write(&mut mem, 1500 + round % 300, 0xa5);
                        write(&mut mem, 40 + round % 8, 0x5a);
                    }
                    _ => {
                        for p in 32..96 {
                            write(&mut mem, p, round as u8 | 1);
                        }
                    }
                }
                reset(&mut state, &mut mem);
                assert!(all_zero(&mut mem), "round {round}");
            }
        }
    }

    /// A reset reading `PAGEMAP_SCAN` ranges, and one reading entries a
    /// page.
    fn states() -> [ScratchReset; 2] {
        [
            ScratchReset::default(),
            ScratchReset {
                no_ranges: true,
                ..ScratchReset::default()
            },
        ]
    }

    /// Both ways of reading pagemap leave every page alike.
    #[test]
    fn ranges_and_entries_agree() {
        let pages = 4096;
        let run = |state: &mut ScratchReset| {
            let mut mem = region(pages);
            for p in 0..1000 {
                write(&mut mem, p, 1);
            }
            reset(state, &mut mem);
            for p in (0..100).step_by(3) {
                write(&mut mem, p, 1);
            }
            for p in 2000..2100 {
                assert_eq!(mem.as_mut_slice()[p * page()], 0);
            }
            write(&mut mem, pages - 1, 1);
            reset(state, &mut mem);
            assert!(all_zero(&mut mem));
            (0..pages)
                .map(|p| {
                    let e = entry(&mem, p);
                    (kept(e), held(e))
                })
                .collect::<Vec<_>>()
        };
        let [mut ranges, mut entries] = states();
        assert_eq!(run(&mut ranges), run(&mut entries));
    }

    /// From Linux 6.7, resets read ranges, not entries a page: the ioctl
    /// is only missing (ENOTTY) before that, and any other failure is a
    /// wrong call.
    #[test]
    fn ranges_are_read_where_supported() {
        let mut mem = region(64);
        write(&mut mem, 3, 1);
        let file = File::open("/proc/self/pagemap").unwrap();
        let mut ranges = [PageRegion::default(); 4];
        let base = mem.base_ptr() as u64;
        let mut arg = PmScanArg::new(base, base + 64 * page() as u64);
        match pagemap_scan(&file, &mut arg, &mut ranges) {
            Err(e) if e.raw_os_error() == Some(libc::ENOTTY) => {
                eprintln!("no PAGEMAP_SCAN: ranges_are_read_where_supported skipped");
                return;
            }
            result => assert_eq!(result.unwrap(), 1),
        }
        assert_eq!(ranges[0].start, base + 3 * page() as u64);
        assert_eq!(ranges[0].categories & PAGE_IS_PRESENT, PAGE_IS_PRESENT);
        let [mut ranges, mut entries] = states();
        reset(&mut ranges, &mut mem);
        assert!(ranges.read_ranges && !NO_RANGES.load(Ordering::Relaxed));
        reset(&mut entries, &mut mem);
        assert!(!entries.read_ranges);
    }

    /// A scan goes on where a call that filled its ranges stopped.
    #[test]
    fn a_scan_continues_past_full_ranges() {
        let pages = SCAN_RANGES * 8;
        let run = |state: &mut ScratchReset| {
            let mut mem = region(pages);
            // Every other page, so each is a range of its own.
            for p in (0..pages).step_by(2) {
                write(&mut mem, p, 1);
            }
            reset(state, &mut mem);
            assert!(all_zero(&mut mem));
            (0..pages).map(|p| kept(entry(&mem, p))).collect::<Vec<_>>()
        };
        let [mut ranges, mut entries] = states();
        let kept = run(&mut ranges);
        assert!(kept.iter().step_by(2).all(|&k| k));
        assert_eq!(kept, run(&mut entries));
    }

    #[test]
    fn pagemap_bits() {
        assert!(!kept(0) && !held(0));
        assert!(kept(PM_PRESENT | PM_EXCLUSIVE));
        assert!(!kept(PM_PRESENT) && held(PM_PRESENT));
        assert!(!kept(PM_SWAPPED) && held(PM_SWAPPED));
    }

    /// The pages a run wrote stay backed from the first reset on, however
    /// many there are.
    #[test]
    fn written_pages_stay_backed() {
        for mut state in states() {
            let mut mem = region(8192);
            for p in 0..8192 {
                write(&mut mem, p, 1);
            }
            reset(&mut state, &mut mem);
            assert!((0..8192).all(|p| kept(entry(&mem, p))));
            assert!(all_zero(&mut mem));
        }
    }

    /// Pages holding only zeros stay backed until a reset gives them
    /// back: a guest that writes zeros to a page every run would
    /// otherwise fault on it every run. What stays resident then follows
    /// the last run, not the most any run wrote.
    #[test]
    fn zero_pages_stay_until_given_back() {
        for mut state in states() {
            let mut mem = region(2048);
            for p in 0..512 {
                write(&mut mem, p, 1);
            }
            reset(&mut state, &mut mem);
            assert!(kept(entry(&mem, 300)));
            write(&mut mem, 0, 1);
            write(&mut mem, 301, 0);
            for _ in 2..GIVE_BACK_EVERY {
                reset(&mut state, &mut mem);
                assert!((0..512).all(|p| kept(entry(&mem, p))));
            }
            assert_eq!(state.resets, GIVE_BACK_EVERY - 1);
            write(&mut mem, 0, 1);
            reset(&mut state, &mut mem);
            assert!(kept(entry(&mem, 0)));
            assert!((1..512).all(|p| !held(entry(&mem, p))));
            assert!(all_zero(&mut mem));
        }
    }

    /// Sparse writes across an earlier, larger footprint leave many runs
    /// of zero pages. Those are dropped up to the limit and otherwise
    /// left, but never make the reset drop everything.
    #[test]
    fn sparse_writes_keep_their_pages() {
        for mut state in states() {
            let mut mem = region(4096);
            for p in 0..4096 {
                write(&mut mem, p, 1);
            }
            reset(&mut state, &mut mem);
            for p in (0..4096).step_by(16) {
                write(&mut mem, p, 1);
            }
            give_back(&mut state, &mut mem);
            assert!((0..4096).step_by(16).all(|p| kept(entry(&mem, p))));
            assert!(all_zero(&mut mem));
        }
    }

    /// The zero page a read maps holds no data: it is left like an
    /// unwritten page, and given back like one, never as a run that must
    /// go.
    #[test]
    fn zero_page_reads_are_left_as_unwritten() {
        for mut state in states() {
            let mut mem = region(512);
            write(&mut mem, 10, 1);
            write(&mut mem, 200, 1);
            reset(&mut state, &mut mem);
            for p in (11..200).step_by(2) {
                assert_eq!(mem.as_mut_slice()[p * page()], 0);
            }
            for give_back in [false, true] {
                write(&mut mem, 10, 1);
                write(&mut mem, 200, 1);
                assert_eq!(
                    state
                        .scan(
                            &mut Region {
                                pages: 512,
                                mem: &mut mem
                            },
                            give_back
                        )
                        .unwrap(),
                    0
                );
                assert_eq!(held(entry(&mem, 11)), !give_back);
            }
            assert!(kept(entry(&mem, 10)) && kept(entry(&mem, 200)));
            assert!(all_zero(&mut mem));
        }
    }

    /// A run not kept is one drop however many pagemap chunks it spans:
    /// more separate drops than [`MAX_DROPS`] would leave some of it.
    #[test]
    fn a_run_across_chunks_is_one_drop() {
        for mut state in states() {
            let chunks = MAX_DROPS + 4;
            let pages = CHUNK_PAGES * chunks;
            let mut mem = region(pages);
            for c in 0..chunks {
                write(&mut mem, c * CHUNK_PAGES + 7, 1);
            }
            write(&mut mem, 0, 1);
            write(&mut mem, pages - 1, 1);
            reset(&mut state, &mut mem);
            // Only the ends written again: what lies between is left zero.
            write(&mut mem, 0, 1);
            write(&mut mem, pages - 1, 1);
            give_back(&mut state, &mut mem);
            assert!((0..chunks).all(|c| !held(entry(&mem, c * CHUNK_PAGES + 7))));
            assert!(kept(entry(&mem, 0)) && kept(entry(&mem, pages - 1)));
        }
    }

    /// Runs that must go always drop, and past [`MAX_DROPS`] of them the
    /// reset drops everything. Runs holding only zeros drop only on a
    /// reset that gives them back, up to their own budget, then stay.
    #[test]
    fn drop_limits() {
        let mut mem = region(16);
        let mut region = Region {
            pages: 16,
            mem: &mut mem,
        };
        let run = |shared, zero| Run {
            start: 0,
            keep: false,
            shared,
            zero,
        };
        let mut drops = Drops::default();
        for _ in 0..MAX_DROPS {
            assert!(!run(true, false).end(&mut region, 1, &mut drops).unwrap());
        }
        assert!(run(true, false).end(&mut region, 1, &mut drops).unwrap());
        for give_back in [false, true] {
            let mut drops = Drops {
                give_back,
                ..Drops::default()
            };
            for _ in 0..MAX_DROPS + 10 {
                assert!(!run(false, true).end(&mut region, 1, &mut drops).unwrap());
            }
            let zero = if give_back { MAX_DROPS } else { 0 };
            assert_eq!((drops.shared, drops.zero), (0, zero));
        }
    }

    /// A page in swap holds the guest's data. The reset drops it.
    #[test]
    fn a_swapped_page_is_dropped() {
        for mut state in states() {
            let mut mem = region(512);
            write(&mut mem, 10, 0x77);
            // SAFETY: the test's own mapping.
            unsafe {
                libc::madvise(
                    mem.base_ptr().add(10 * page()) as *mut libc::c_void,
                    page(),
                    libc::MADV_PAGEOUT,
                )
            };
            if entry(&mem, 10) & PM_SWAPPED == 0 {
                eprintln!("no swap: a_swapped_page_is_dropped skipped");
                return;
            }
            reset(&mut state, &mut mem);
            assert!(all_zero(&mut mem));
        }
    }

    /// A forked child resets its own pages, not the ones its parent's
    /// pagemap shows. After the fork the parent writes pages 10 and 20
    /// again, so its pagemap shows them as its own and page 15, which the
    /// child wrote, as empty: a reset reading it would leave page 15.
    /// Page 40 holds data shared with the child at the fork, which the
    /// child's reset must not leave; the child keeps page 39 so page 40
    /// is not in a run dropped anyway.
    /// Ignored: it forks, so `forked_child_shim` runs it alone in a
    /// process of its own, away from the pages and locks of tests running
    /// in parallel.
    #[test]
    #[ignore]
    fn a_forked_child_resets_its_own_pages() {
        for state in states() {
            forked_child_resets(state);
        }
    }

    fn forked_child_resets(mut state: ScratchReset) {
        let mut mem = region(512);
        write(&mut mem, 10, 1);
        write(&mut mem, 20, 1);
        reset(&mut state, &mut mem);
        assert_eq!(
            process_pagemap().map(|(pid, _)| *pid),
            Some(std::process::id())
        );
        assert!(state.forked.is_none());
        write(&mut mem, 40, 0x33);
        let mut fds = [0; 2];
        // SAFETY: two valid fds for the pipe.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: the process runs this test alone (`forked_child_shim`).
        // The child waits for the parent, writes its copy of `mem`, resets
        // it (opening pagemap, which allocates), and exits without
        // unwinding.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let mut byte = 0u8;
            // SAFETY: reads one byte into `byte` from the pipe.
            unsafe { libc::read(fds[0], (&mut byte as *mut u8).cast(), 1) };
            let ok = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                write(&mut mem, 15, 0x5a);
                write(&mut mem, 39, 0x5a);
                state.reset(&mut mem).is_ok()
                    && all_zero(&mut mem)
                    && state.forked.as_ref().map(|(pid, _)| *pid) == Some(std::process::id())
            }));
            // SAFETY: ends the child.
            unsafe { libc::_exit(if matches!(ok, Ok(true)) { 0 } else { 1 }) };
        }
        write(&mut mem, 10, 2);
        write(&mut mem, 20, 2);
        assert!(kept(entry(&mem, 10)) && !held(entry(&mem, 15)));
        // SAFETY: writes one byte to the pipe, then waits for the child.
        let mut status = 0;
        unsafe {
            libc::write(fds[1], [1u8].as_ptr().cast(), 1);
            libc::waitpid(pid, &mut status, 0);
        }
        assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);
    }

    #[test]
    fn forked_child_shim() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "--test-threads=1",
                "mem::scratch_reset::tests::a_forked_child_resets_its_own_pages",
            ])
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "{stdout}{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// Without pagemap, a reset fails, and the caller drops the region
    /// instead. Pagemap is not tried again for the sandbox.
    #[test]
    fn without_pagemap_a_reset_fails() {
        let mut mem = region(512);
        let mut state = ScratchReset {
            fail_pagemap: true,
            ..ScratchReset::default()
        };
        write(&mut mem, 10, 1);
        assert!(state.reset(&mut mem).is_err());
        assert_eq!(state.unusable, Some(std::process::id()));
        state.fail_pagemap = false;
        assert!(state.reset(&mut mem).is_err());
    }

    /// Pages that must go (here, in swap) scattered so that a reset would
    /// drop them one by one are dropped all at once.
    #[test]
    fn scattered_swapped_pages_are_dropped_wholesale() {
        for mut state in states() {
            let mut mem = region(2048);
            for p in (0..400).step_by(2) {
                write(&mut mem, p, 1);
                write(&mut mem, p + 1, 2);
                // SAFETY: the test's own mapping.
                unsafe {
                    libc::madvise(
                        mem.base_ptr().add((p + 1) * page()) as *mut libc::c_void,
                        page(),
                        libc::MADV_PAGEOUT,
                    )
                };
            }
            if entry(&mem, 1) & PM_SWAPPED == 0 {
                eprintln!("no swap: scattered_swapped_pages_are_dropped_wholesale skipped");
                return;
            }
            reset(&mut state, &mut mem);
            assert!(!kept(entry(&mem, 0)));
            assert!(all_zero(&mut mem));
        }
    }
}
