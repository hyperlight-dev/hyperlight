/*
Copyright 2026 The Hyperlight Authors.

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

//! Pool of HVF surrogate server processes for aarch64 macOS.
//!
//! HVF allows only one VM per process, so each concurrent sandbox delegates
//! its VM to an `hvf_surrogate` server process (see
//! `src/hyperlight_host/src/hvf_surrogate`). This module mirrors the Windows
//! `surrogate_process_manager`: it embeds the surrogate binary (and the
//! hypervisor entitlement plist) via rust-embed, extracts them next to the
//! running executable, ad-hoc codesigns the binary, and hands out pooled
//! processes. Each checked-out [`HvfSurrogateProcess`] owns one end of a
//! socketpair speaking the [`hyperlight_hvf::proto`] protocol; dropping the
//! handle returns a still-alive process to the pool.
//!
//! Sizing is controlled by `HYPERLIGHT_INITIAL_SURROGATES` (default 0 —
//! unlike the suspended Windows shells these are real running server
//! processes, so they are spawned on demand) and `HYPERLIGHT_MAX_SURROGATES`
//! (default 128, matched to the platform's concurrent-VM cap; `0` disables
//! surrogates entirely, see [`surrogates_disabled`]).

use std::os::unix::io::FromRawFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use crossbeam_channel::{Receiver, Sender, TryRecvError, unbounded};
use rust_embed::RustEmbed;
use tracing::{error, info, warn};

use crate::{Result, new_error};

// Use the rust-embed crate to embed the hvf_surrogate binary in the
// hyperlight-host library to make dependency management easier.
// $HYPERLIGHT_HVF_SURROGATE_DIR is set by hyperlight-host's build.rs script.
// https://docs.rs/rust-embed/latest/rust_embed/
#[derive(RustEmbed)]
#[folder = "$HYPERLIGHT_HVF_SURROGATE_DIR"]
#[include = "hvf_surrogate"]
struct Asset;

/// The name of the embedded surrogate asset (used as the key for `Asset::get`).
const EMBEDDED_SURROGATE_NAME: &str = "hvf_surrogate";

/// The entitlements plist embedded in this library; extracted next to the
/// surrogate binary and applied with `codesign` on extraction. The path is
/// set by hyperlight-host's build.rs script.
const ENTITLEMENTS_PLIST: &[u8] = include_bytes!(env!("HYPERLIGHT_HVF_ENTITLEMENTS_PATH"));

/// Environment variable passed to the surrogate carrying its inherited
/// control-socket fd.
const SURROGATE_FD_ENV_VAR: &str = "HVF_SURROGATE_FD";

/// Environment variable controlling how many surrogate processes are
/// pre-created when the manager starts. Must be <=
/// `HYPERLIGHT_MAX_SURROGATES`. Defaults to 0 (created on demand).
const INITIAL_SURROGATES_ENV_VAR: &str = "HYPERLIGHT_INITIAL_SURROGATES";

/// Environment variable controlling the maximum number of surrogate
/// processes that can exist (including those created on demand). Must be >=
/// `HYPERLIGHT_INITIAL_SURROGATES`. Defaults to 64. `0` disables
/// surrogates entirely.
const MAX_SURROGATES_ENV_VAR: &str = "HYPERLIGHT_MAX_SURROGATES";

/// Default maximum number of surrogate processes. Sized to the platform's
/// concurrent-VM limit: macOS caps HVF VMs system-wide (measured 127 on
/// macOS 26, arm64), so a larger pool only stockpiles idle processes, and
/// a smaller one can deadlock threads that hold one surrogate while
/// acquiring another (pool backpressure is the correct behavior near the
/// cap; exceeding it yields a clean `HV_NO_RESOURCES` error).
const DEFAULT_MAX_SURROGATE_PROCESSES: usize = 128;

/// A pooled surrogate process: the child handle plus our end of the
/// control socketpair.
struct PooledSurrogate {
    child: Child,
    socket: UnixStream,
}

/// A surrogate process checked out from the pool. Dropping it returns the
/// process to the pool if it is still alive, and reaps it otherwise.
pub(crate) struct HvfSurrogateProcess {
    /// `Some` while checked out; taken by `Drop`.
    inner: Option<PooledSurrogate>,
    /// Channel back to the owning manager's pool.
    return_sender: Sender<PooledSurrogate>,
    /// Shared with the owning manager; decremented when this process dies
    /// and is not returned, freeing capacity for a replacement.
    created_count: Arc<AtomicUsize>,
}

impl HvfSurrogateProcess {
    /// The control socket connected to the surrogate server (clone it with
    /// `try_clone` to share it across threads).
    pub(crate) fn socket(&self) -> &UnixStream {
        &self
            .inner
            .as_ref()
            .expect("socket is only accessible while checked out")
            .socket
    }

    /// Returns `true` if the surrogate process is still running.
    #[allow(dead_code)] // used by tests; kept for diagnostics
    pub(crate) fn is_alive(&mut self) -> bool {
        self.inner
            .as_mut()
            .is_some_and(|p| matches!(p.child.try_wait(), Ok(None)))
    }
}

impl Drop for HvfSurrogateProcess {
    fn drop(&mut self) {
        let Some(mut pooled) = self.inner.take() else {
            return;
        };
        match pooled.child.try_wait() {
            Ok(None) => {
                // Still alive: return it to the pool. If the manager is
                // already gone, kill and reap the process instead.
                if let Err(crossbeam_channel::SendError(mut pooled)) =
                    self.return_sender.send(pooled)
                {
                    let _ = pooled.child.kill();
                    let _ = pooled.child.wait();
                }
            }
            _ => {
                // Already exited (reaped by `try_wait`): free up capacity
                // for a replacement.
                self.created_count.fetch_sub(1, Ordering::AcqRel);
            }
        }
    }
}

/// `HvfSurrogateProcessManager` manages `hvf_surrogate` processes. These
/// processes are required to run multiple HVF VMs from a single host
/// process: each surrogate owns one VM and is driven over a unix
/// socketpair using the [`hyperlight_hvf::proto`] protocol.
///
/// This struct deals with the creation/destruction of these processes, the
/// pooling of process handles, the distribution of handles from the pool to
/// a Hyperlight Sandbox instance and the return of a handle to the pool
/// once the Sandbox instance is destroyed. It is intended to be used as a
/// singleton and is thread safe.
///
/// By default no processes are pre-created; additional processes are
/// created on demand up to `HYPERLIGHT_MAX_SURROGATES` (default 64). If the
/// pool is empty and the max has been reached, callers block until a
/// process is returned.
pub(crate) struct HvfSurrogateProcessManager {
    /// `process_receiver` and `process_sender` synchronize reserving a
    /// surrogate process from the pool and returning one to the pool. See
    /// the Windows `SurrogateProcessManager` for why these are
    /// crossbeam-channel types (`Send + Sync`).
    process_receiver: Receiver<PooledSurrogate>,
    process_sender: Sender<PooledSurrogate>,
    /// Path to the on-disk surrogate binary (hash-stamped).
    surrogate_process_path: PathBuf,
    /// Maximum number of surrogate processes allowed to exist.
    max_processes: usize,
    /// Number of surrogate processes created so far (minus those observed
    /// dead). Used to decide whether we can spawn more on demand.
    created_count: Arc<AtomicUsize>,
}

impl HvfSurrogateProcessManager {
    fn new() -> Result<Self> {
        let binary_name = surrogate_binary_name()?;
        ensure_surrogate_exe(&binary_name)?;
        let surrogate_process_path = get_surrogate_process_dir()?.join(&binary_name);

        let (initial, max) = surrogate_process_counts();

        let (sender, receiver) = unbounded();
        let manager = HvfSurrogateProcessManager {
            process_receiver: receiver,
            process_sender: sender,
            surrogate_process_path,
            max_processes: max,
            created_count: Arc::new(AtomicUsize::new(0)),
        };

        info!(
            "pre-creating {} hvf surrogate processes ({}={:?}, {}={:?})",
            initial,
            INITIAL_SURROGATES_ENV_VAR,
            std::env::var(INITIAL_SURROGATES_ENV_VAR).ok(),
            MAX_SURROGATES_ENV_VAR,
            std::env::var(MAX_SURROGATES_ENV_VAR).ok(),
        );
        for _ in 0..initial {
            let pooled = spawn_surrogate_process(&manager.surrogate_process_path)?;
            manager
                .process_sender
                .send(pooled)
                .map_err(|e| new_error!("surrogate process channel disconnected: {}", e))?;
            manager.created_count.fetch_add(1, Ordering::AcqRel);
        }

        Ok(manager)
    }

    /// Gets a surrogate process from the pool. If the pool is empty and
    /// fewer than `max_processes` have been created, a new process is
    /// spawned on demand. If the pool is empty and the maximum has been
    /// reached, this call blocks until a process is returned. Dead pooled
    /// processes are reaped and skipped.
    pub(crate) fn get_surrogate_process(&self) -> Result<HvfSurrogateProcess> {
        // Fast path: try to grab an already-pooled process.
        loop {
            match self.process_receiver.try_recv() {
                Ok(mut pooled) => {
                    if matches!(pooled.child.try_wait(), Ok(None)) {
                        return Ok(self.wrap(pooled));
                    }
                    // Dead (reaped by `try_wait`): free the slot and look
                    // for another pooled process.
                    self.created_count.fetch_sub(1, Ordering::AcqRel);
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    return Err(new_error!("surrogate process channel disconnected"));
                }
            }
        }

        // On-demand growth: atomically claim a slot if one is available.
        // We use a CAS loop so that concurrent callers don't overshoot
        // the maximum.
        loop {
            let current = self.created_count.load(Ordering::Acquire);
            if current >= self.max_processes {
                // At the limit — fall through to the blocking recv below.
                break;
            }
            if self
                .created_count
                .compare_exchange(current, current + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                info!(
                    "on-demand hvf surrogate process creation ({}/{})",
                    current + 1,
                    self.max_processes
                );
                match spawn_surrogate_process(&self.surrogate_process_path) {
                    Ok(pooled) => return Ok(self.wrap(pooled)),
                    Err(e) => {
                        // Rollback the slot claim so capacity isn't
                        // permanently lost on transient failures.
                        self.created_count.fetch_sub(1, Ordering::AcqRel);
                        return Err(e);
                    }
                }
            }
            // CAS failed — another thread beat us; retry.
        }

        // Maximum reached — block until a process is returned to the pool.
        loop {
            let mut pooled = self
                .process_receiver
                .recv()
                .map_err(|e| new_error!("surrogate process channel disconnected: {}", e))?;
            if matches!(pooled.child.try_wait(), Ok(None)) {
                return Ok(self.wrap(pooled));
            }
            self.created_count.fetch_sub(1, Ordering::AcqRel);
        }
    }

    /// Wrap a pooled process in a checkout handle that returns itself to
    /// this pool on drop.
    fn wrap(&self, pooled: PooledSurrogate) -> HvfSurrogateProcess {
        HvfSurrogateProcess {
            inner: Some(pooled),
            return_sender: self.process_sender.clone(),
            created_count: Arc::clone(&self.created_count),
        }
    }
}

impl Drop for HvfSurrogateProcessManager {
    fn drop(&mut self) {
        // Kill and reap every pooled process. Checked-out processes are
        // handled by their own drop.
        while let Ok(mut pooled) = self.process_receiver.try_recv() {
            if let Err(e) = pooled.child.kill() {
                error!("failed to kill hvf surrogate process: {}", e);
            }
            let _ = pooled.child.wait();
        }
    }
}

/// Gets the singleton `HvfSurrogateProcessManager`.
pub(crate) fn get_hvf_surrogate_process_manager() -> Result<&'static HvfSurrogateProcessManager> {
    static MANAGER: OnceLock<std::result::Result<HvfSurrogateProcessManager, String>> =
        OnceLock::new();
    MANAGER
        .get_or_init(|| {
            HvfSurrogateProcessManager::new().map_err(|e| {
                error!("Failed to create HvfSurrogateProcessManager: {:?}", e);
                format!("{e}")
            })
        })
        .as_ref()
        .map_err(|e| new_error!("Failed to get HvfSurrogateProcessManager: {}", e))
}

/// Returns `true` when `HYPERLIGHT_MAX_SURROGATES=0`, meaning surrogate
/// processes are disabled and the direct in-process HVF backend
/// (single-VM-per-process mode) should be used instead.
///
/// The result is cached on first call — the env var is read only once.
pub(crate) fn surrogates_disabled() -> bool {
    static DISABLED: OnceLock<bool> = OnceLock::new();
    *DISABLED.get_or_init(|| {
        std::env::var(MAX_SURROGATES_ENV_VAR)
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .is_some_and(|n| n == 0)
    })
}

/// Returns the on-disk filename for the surrogate binary, incorporating the
/// first 8 hex characters of the BLAKE3 hash of the embedded binary and the
/// entitlements plist, so that different hyperlight versions produce
/// different filenames and can coexist without file-deletion races.
fn surrogate_binary_name() -> Result<String> {
    let exe = Asset::get(EMBEDDED_SURROGATE_NAME)
        .ok_or_else(|| new_error!("could not find embedded hvf surrogate binary"))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(exe.data.as_ref());
    hasher.update(ENTITLEMENTS_PLIST);
    let short_hash = &hasher.finalize().to_hex()[..8];
    Ok(format!("hvf_surrogate_{short_hash}"))
}

/// Pure validation/clamping logic for surrogate process counts.
///
/// `raw_initial` and `raw_max` are the parsed values from the environment
/// (or `None` when the variable is unset or unparsable).
///
/// Resolution order:
/// 1. `max` defaults to [`DEFAULT_MAX_SURROGATE_PROCESSES`] when `None`.
/// 2. `initial` is clamped to `0..=max`, defaulting to 0 when `None`.
///
/// When `max == 0`, surrogates are disabled entirely and the system falls
/// back to the direct in-process HVF backend.
fn compute_surrogate_counts(raw_initial: Option<usize>, raw_max: Option<usize>) -> (usize, usize) {
    let max = raw_max.unwrap_or(DEFAULT_MAX_SURROGATE_PROCESSES);

    // Clamp initial to 0..=max so it can never exceed the authoritative limit.
    let initial = raw_initial.map(|n| n.clamp(0, max)).unwrap_or(0);

    (initial, max)
}

/// Returns the (initial, max) surrogate process counts from environment
/// variables, applying validation and clamping.
///
/// - `HYPERLIGHT_INITIAL_SURROGATES`: clamped to `0..=max`, default 0.
/// - `HYPERLIGHT_MAX_SURROGATES`: default 128; `0` disables surrogates.
fn surrogate_process_counts() -> (usize, usize) {
    let raw_initial = std::env::var(INITIAL_SURROGATES_ENV_VAR)
        .ok()
        .and_then(|v| v.parse::<usize>().ok());
    let raw_max = std::env::var(MAX_SURROGATES_ENV_VAR)
        .ok()
        .and_then(|v| v.parse::<usize>().ok());

    let (initial, max) = compute_surrogate_counts(raw_initial, raw_max);

    if let Some(n) = raw_initial
        && n != initial
    {
        warn!("{INITIAL_SURROGATES_ENV_VAR}={n} was clamped to {initial}");
    }
    if let Some(n) = raw_max
        && n != max
    {
        warn!("{MAX_SURROGATES_ENV_VAR}={n} was clamped to {max}");
    }

    (initial, max)
}

fn get_surrogate_process_dir() -> Result<PathBuf> {
    let binding = std::env::current_exe()?;
    let path = binding
        .parent()
        .ok_or_else(|| new_error!("could not get parent directory of current executable"))?;

    Ok(path.to_path_buf())
}

/// Ensures the surrogate binary exists on disk at the hash-stamped path,
/// executable and ad-hoc codesigned with the hypervisor entitlement
/// (without it `hv_vm_create` fails in the surrogate).
///
/// The filename embeds the content hash of the binary and the plist, and
/// extraction writes to a pid-stamped temporary file that is atomically
/// renamed into place after signing, so any visible hash-stamped file is
/// complete and signed.
fn ensure_surrogate_exe(binary_name: &str) -> Result<()> {
    let dir = get_surrogate_process_dir()?;
    let final_path = dir.join(binary_name);
    if final_path.exists() {
        return Ok(());
    }

    let exe = Asset::get(EMBEDDED_SURROGATE_NAME)
        .ok_or_else(|| new_error!("could not find embedded hvf surrogate binary"))?;

    let tmp_path = dir.join(format!(".{binary_name}.tmp-{}", std::process::id()));
    let plist_path = dir.join(format!("{binary_name}.entitlements.plist"));

    let result = (|| -> Result<()> {
        std::fs::write(&tmp_path, exe.data.as_ref())?;
        std::fs::set_permissions(
            &tmp_path,
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o755),
        )?;
        std::fs::write(&plist_path, ENTITLEMENTS_PLIST)?;
        let status = Command::new("codesign")
            .arg("--sign")
            .arg("-")
            .arg("--entitlements")
            .arg(&plist_path)
            .arg("--force")
            .arg(&tmp_path)
            .status()?;
        if !status.success() {
            return Err(new_error!("codesign of hvf surrogate failed: {}", status));
        }
        info!(
            "extracted and codesigned hvf surrogate to {}",
            final_path.display()
        );
        match std::fs::rename(&tmp_path, &final_path) {
            Ok(()) => Ok(()),
            // Lost a race with a concurrent extractor; the winner's file
            // is content-identical.
            Err(_) if final_path.exists() => Ok(()),
            Err(e) => Err(e.into()),
        }
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    result
}

/// Spawns a surrogate process with one end of a fresh socketpair inherited
/// as its control socket.
fn spawn_surrogate_process(exe_path: &Path) -> Result<PooledSurrogate> {
    let mut fds = [0i32; 2];
    // SAFETY: `fds` is a valid two-element array; on success both
    // descriptors are owned by us. No SOCK_CLOEXEC: the child end must
    // survive the exec of the surrogate binary.
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let (parent_fd, child_fd) = (fds[0], fds[1]);

    // Mark our end close-on-exec: without this the surrogate would inherit
    // a duplicate of the parent's end too, and would then never see EOF
    // when the parent closes its end (its own duplicate keeps the socket
    // open).
    // SAFETY: `parent_fd` is a live descriptor owned by us.
    if unsafe { libc::fcntl(parent_fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
        let err = std::io::Error::last_os_error();
        // SAFETY: both descriptors are live and owned by us.
        unsafe {
            libc::close(parent_fd);
            libc::close(child_fd);
        }
        return Err(err.into());
    }

    let spawn_result = Command::new(exe_path)
        .env(SURROGATE_FD_ENV_VAR, child_fd.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .spawn();

    // The child (if any) has inherited its end by now; the parent never
    // uses it again.
    // SAFETY: `child_fd` is a live descriptor owned by us.
    unsafe {
        libc::close(child_fd);
    }

    let child = match spawn_result {
        Ok(child) => child,
        Err(e) => {
            // SAFETY: `parent_fd` is a live descriptor owned by us.
            unsafe {
                libc::close(parent_fd);
            }
            return Err(e.into());
        }
    };

    // SAFETY: `parent_fd` is a live socket descriptor owned by us.
    let socket = unsafe { UnixStream::from_raw_fd(parent_fd) };
    Ok(PooledSurrogate { child, socket })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use hyperlight_hvf::proto::{PROTO_VERSION, Request, Response, read_frame, write_frame};

    use super::*;

    fn handshake(sock: &UnixStream) {
        let mut s = sock;
        write_frame(
            &mut s,
            &Request::Hello {
                version: PROTO_VERSION,
            },
        )
        .unwrap();
        match read_frame::<Response>(&mut s).unwrap() {
            Some(Response::Hello { version }) => assert_eq!(version, PROTO_VERSION),
            other => panic!("unexpected handshake response: {other:?}"),
        }
    }

    fn request(sock: &UnixStream, req: &Request) -> Response {
        let mut s = sock;
        write_frame(&mut s, req).unwrap();
        read_frame::<Response>(&mut s)
            .unwrap()
            .expect("surrogate closed the connection")
    }

    fn connect(sock: &UnixStream) -> UnixStream {
        let s = sock.try_clone().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        s
    }

    /// Protocol-level cancellation probe: map a shm region containing an
    /// infinite loop (`b .`), run the vCPU, and cancel it from another
    /// thread. The run must exit with `VmExit::Cancelled`.
    #[test]
    fn surrogate_cancel_interrupts_run() {
        use std::ffi::CString;

        use hyperlight_hvf::core::{Perms, Regs, VmExit};
        use hyperlight_hvf::proto::Backing;

        let mgr = get_hvf_surrogate_process_manager().unwrap();
        let mut proc = mgr.get_surrogate_process().unwrap();
        let sock = connect(proc.socket());
        handshake(&sock);
        assert!(matches!(request(&sock, &Request::CreateVm), Response::Ok));

        // Guest memory: one page with `b .` (0x14000000) at the start.
        const SIZE: usize = 0x4000;
        const GPA: u64 = 0x4000_0000;
        let name = format!("/hl-{}-cancel", std::process::id());
        let c_name = CString::new(name.as_str()).unwrap();
        // SAFETY: `c_name` is a valid NUL-terminated string; flags/mode are
        // valid. On success the fd is ours.
        let fd = unsafe {
            libc::shm_open(
                c_name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
                0o600,
            )
        };
        assert!(
            fd >= 0,
            "shm_open failed: {:?}",
            std::io::Error::last_os_error()
        );
        // SAFETY: `fd` is a live shm descriptor we just created.
        assert_eq!(unsafe { libc::ftruncate(fd, SIZE as libc::off_t) }, 0);
        // SAFETY: `fd` is a live shm descriptor of SIZE bytes.
        let va = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        assert_ne!(va, libc::MAP_FAILED);
        // `b .` — branch to self, an infinite loop.
        // SAFETY: `va` points to a live writable mapping of SIZE bytes.
        unsafe { (va as *mut u32).write(0x1400_0000) };

        assert!(matches!(
            request(
                &sock,
                &Request::MapMemory {
                    slot: 0,
                    gpa: GPA,
                    size: SIZE as u64,
                    perms: Perms {
                        read: true,
                        write: false,
                        exec: true,
                    },
                    backing: Backing::Shm {
                        name: name.clone(),
                        offset: 0,
                    },
                }
            ),
            Response::Ok
        ));

        // Run with MMU off (fresh vCPU: SCTLR_EL1 reset value), PC at GPA,
        // EL1t with interrupts masked — same pstate the host uses.
        let regs = Regs {
            pc: GPA,
            pstate: 0b11 << 6 | 0b100,
            ..Default::default()
        };
        assert!(matches!(
            request(&sock, &Request::SetRegs(regs)),
            Response::Ok
        ));

        // Cancel from another thread after 200ms (a cloned fd, mirroring
        // the interrupt handle's shared writer).
        let cancel_sock = sock.try_clone().unwrap();
        let cancel_thread = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            let mut s = &cancel_sock;
            write_frame(&mut s, &Request::Cancel).unwrap();
        });

        let resp = request(&sock, &Request::RunVcpu);
        cancel_thread.join().unwrap();
        assert!(
            matches!(resp, Response::Exit(VmExit::Cancelled)),
            "expected Exit(Cancelled), got {resp:?}"
        );

        assert!(matches!(request(&sock, &Request::DestroyVm), Response::Ok));

        // SAFETY: `va`/`fd`/`name` are the live mapping, descriptor and
        // object created above.
        unsafe {
            libc::munmap(va, SIZE);
            libc::close(fd);
            libc::shm_unlink(c_name.as_ptr());
        }
    }

    /// Smoke test: acquire a surrogate, complete the handshake, create a
    /// VM, round-trip the system registers with a known value, destroy the
    /// VM, and return the process to the pool — then verify the pooled
    /// process is reused for another full VM lifecycle.
    ///
    /// The test binary must be codesigned with
    /// `dev/hvf-entitlements.plist` (see the `test-hvf` just recipe).
    #[test]
    fn surrogate_handshake_and_sregs_round_trip() {
        let mgr = get_hvf_surrogate_process_manager().unwrap();
        assert!(!surrogates_disabled());

        let mut proc = mgr.get_surrogate_process().unwrap();
        assert!(proc.is_alive());
        let sock = connect(proc.socket());

        handshake(&sock);
        assert!(matches!(request(&sock, &Request::CreateVm), Response::Ok));

        // Round-trip sregs with a known value.
        let Response::Sregs(mut sregs) = request(&sock, &Request::GetSregs) else {
            panic!("expected Sregs");
        };
        sregs.sp_el1 = 0x1234_5000;
        assert!(matches!(
            request(&sock, &Request::SetSregs(sregs)),
            Response::Ok
        ));
        let Response::Sregs(got) = request(&sock, &Request::GetSregs) else {
            panic!("expected Sregs");
        };
        assert_eq!(got, sregs);

        assert!(matches!(request(&sock, &Request::DestroyVm), Response::Ok));

        // Return the process to the pool; re-acquiring must yield a live,
        // reusable surrogate.
        drop(proc);
        let mut proc2 = mgr.get_surrogate_process().unwrap();
        assert!(proc2.is_alive());
        let sock2 = connect(proc2.socket());
        handshake(&sock2);
        assert!(matches!(request(&sock2, &Request::CreateVm), Response::Ok));
        assert!(matches!(request(&sock2, &Request::DestroyVm), Response::Ok));
    }

    /// Verifies `compute_surrogate_counts()` returns sensible defaults
    /// when inputs are `None`, and correct clamped values otherwise.
    #[test]
    fn test_compute_surrogate_counts() {
        // Both unset → defaults (initial 0, max 64).
        let (initial, max) = compute_surrogate_counts(None, None);
        assert_eq!(initial, 0);
        assert_eq!(max, DEFAULT_MAX_SURROGATE_PROCESSES);

        // Only initial set → honoured, clamped to max.
        let (initial, max) = compute_surrogate_counts(Some(8), None);
        assert_eq!(initial, 8);
        assert_eq!(max, DEFAULT_MAX_SURROGATE_PROCESSES);

        // Initial above max → clamped down to max.
        let (initial, max) = compute_surrogate_counts(Some(100), Some(10));
        assert_eq!(initial, 10);
        assert_eq!(max, 10);

        // Max at zero → surrogates disabled, initial follows.
        let (initial, max) = compute_surrogate_counts(None, Some(0));
        assert_eq!(initial, 0);
        assert_eq!(max, 0);

        // Both set, max > initial.
        let (initial, max) = compute_surrogate_counts(Some(3), Some(7));
        assert_eq!(initial, 3);
        assert_eq!(max, 7);
    }

    /// Verifies extraction naming is deterministic.
    #[test]
    fn test_surrogate_binary_name_deterministic() {
        let a = surrogate_binary_name().unwrap();
        let b = surrogate_binary_name().unwrap();
        assert_eq!(a, b);
        assert!(a.starts_with("hvf_surrogate_"));
    }
}
