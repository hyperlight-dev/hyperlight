// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

use std::fs::{self, File, OpenOptions};
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use super::launch::{ControlOutcome, ControlResult};
use super::{ProcessControl, RequestedControl};
use crate::{Result, new_error};

pub(super) struct Domain {
    path: PathBuf,
    procs: Arc<OwnedFd>,
    removed: AtomicBool,
    retained: AtomicBool,
}

impl Domain {
    pub(super) fn create(root: &Path) -> Result<Self> {
        let root = root.canonicalize()?;
        let directory = File::open(&root)?;
        let mut status = std::mem::MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: the descriptor is live and status has space for one statfs.
        if unsafe { libc::fstatfs(directory.as_raw_fd(), status.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: fstatfs initialized status after returning zero.
        if unsafe { status.assume_init() }.f_type != libc::CGROUP2_SUPER_MAGIC {
            return Err(new_error!("Delegation root is not a cgroup2 filesystem"));
        }
        let path = root.join(format!("hyperlight-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&path)?;
        let procs = match OpenOptions::new()
            .write(true)
            .open(path.join("cgroup.procs"))
        {
            Ok(file) => file,
            Err(error) => {
                if let Err(cleanup) = fs::remove_dir(&path) {
                    return Err(new_error!(
                        "Opening cgroup enrollment failed: {error}. Rollback failed: {cleanup}"
                    ));
                }
                return Err(error.into());
            }
        };
        Ok(Self {
            path,
            procs: Arc::new(procs.into()),
            removed: AtomicBool::new(false),
            retained: AtomicBool::new(false),
        })
    }

    pub(super) fn procs_fd(&self) -> Arc<OwnedFd> {
        self.procs.clone()
    }

    pub(super) fn configure(&self, request: &RequestedControl) -> Result<ControlOutcome> {
        let effective = match request.control {
            ProcessControl::MemoryLimit(bytes) => {
                let path = self.path.join("memory.max");
                fs::write(&path, bytes.to_string())?;
                let effective = fs::read_to_string(path)?
                    .trim()
                    .parse::<u64>()
                    .map_err(|error| new_error!("Invalid memory.max readback: {error}"))?;
                if effective > bytes {
                    return Err(new_error!("Effective memory limit exceeds its request"));
                }
                ProcessControl::MemoryLimit(effective)
            }
            ProcessControl::CpuBudget { quota, period } => {
                let quota_us = u64::try_from(quota.as_micros())
                    .map_err(|_| new_error!("CPU quota exceeds supported precision"))?;
                let period_us = u64::try_from(period.as_micros())
                    .map_err(|_| new_error!("CPU period exceeds supported precision"))?;
                if Duration::from_micros(quota_us) != quota
                    || Duration::from_micros(period_us) != period
                {
                    return Err(new_error!("CPU budgets require exact microseconds"));
                }
                let requested = format!("{quota_us} {period_us}");
                let path = self.path.join("cpu.max");
                fs::write(&path, &requested)?;
                if fs::read_to_string(path)?.trim() != requested {
                    return Err(new_error!("cpu.max readback does not match its request"));
                }
                request.control.clone()
            }
            _ => return Err(new_error!("Control is not a cgroup resource budget")),
        };
        Ok(ControlOutcome {
            requested: request.clone(),
            result: ControlResult::Applied {
                effective,
                mechanism: "cgroup2 subtree, including the confinement supervisor".to_owned(),
            },
        })
    }

    fn populated(&self) -> Result<bool> {
        let events = fs::read_to_string(self.path.join("cgroup.events"))?;
        match events
            .lines()
            .find_map(|line| line.strip_prefix("populated "))
        {
            Some("0") => Ok(false),
            Some("1") => Ok(true),
            _ => Err(new_error!("Invalid cgroup populated evidence")),
        }
    }
}

impl Domain {
    pub(super) fn retain(&self) {
        self.retained.store(true, Ordering::Release);
    }

    pub(super) fn terminate_domain(&self) -> Result<()> {
        if !self.removed.load(Ordering::Acquire) {
            fs::write(self.path.join("cgroup.kill"), "1")?;
        }
        Ok(())
    }

    pub(super) fn wait_empty(&self, deadline: Instant) -> Result<()> {
        if self.removed.load(Ordering::Acquire) {
            return Ok(());
        }
        while self.populated()? {
            if Instant::now() >= deadline {
                return Err(new_error!(
                    "Process cgroup remains populated: {:?}",
                    self.path
                ));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok(())
    }

    pub(super) fn remove(&self, deadline: Instant) -> Result<()> {
        if self.removed.load(Ordering::Acquire) {
            return Ok(());
        }
        self.wait_empty(deadline)?;
        remove_empty_tree(&self.path)?;
        self.removed.store(true, Ordering::Release);
        Ok(())
    }
}

fn remove_empty_tree(path: &Path) -> Result<()> {
    // cgroup2 supports directories but not symlinks. The owned subtree is empty.
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            remove_empty_tree(&entry.path())?;
        }
    }
    fs::remove_dir(path)?;
    Ok(())
}

impl Drop for Domain {
    fn drop(&mut self) {
        if self.retained.load(Ordering::Acquire) && !self.removed.load(Ordering::Acquire) {
            let termination = self.terminate_domain();
            tracing::error!(?termination, path = ?self.path,
                "Retaining process domain after unconfirmed cleanup");
            return;
        }
        if let Err(error) = self
            .terminate_domain()
            .and_then(|()| self.remove(Instant::now() + Duration::from_secs(30)))
        {
            tracing::error!(?error, path = ?self.path, "Process domain cleanup failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::process::CommandExt;

    use super::*;

    #[test]
    fn rejects_non_cgroup_filesystem_without_creating_a_leaf() {
        let root = tempfile::tempdir().unwrap();
        assert!(Domain::create(root.path()).is_err());
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    }

    #[test]
    #[ignore = "requires explicit delegated driver origin"]
    fn delegated_budgets_enrollment_and_tree_cleanup() {
        let root = std::env::var_os("HYPERLIGHT_TEST_CGROUP_ROOT")
            .expect("Run through the approved delegated driver");
        let domain = Domain::create(Path::new(&root)).unwrap();
        for control in [
            ProcessControl::MemoryLimit(64 * 1024 * 1024),
            ProcessControl::CpuBudget {
                quota: Duration::from_millis(25),
                period: Duration::from_millis(100),
            },
        ] {
            let outcome = domain
                .configure(&RequestedControl {
                    control: control.clone(),
                    required: true,
                })
                .unwrap();
            assert!(
                matches!(outcome.result, ControlResult::Applied { effective, .. } if effective == control)
            );
        }
        let enrollment = domain.procs_fd();
        let mut command = std::process::Command::new("/bin/sh");
        command.args(["-c", "sleep 60 & wait"]);
        // SAFETY: the callback only writes one static byte through a live,
        // captured descriptor. It performs no allocation or synchronization.
        unsafe {
            command.pre_exec(move || {
                loop {
                    if libc::write(enrollment.as_raw_fd(), b"0".as_ptr().cast(), 1) == 1 {
                        return Ok(());
                    }
                    let error = std::io::Error::last_os_error();
                    if error.kind() != std::io::ErrorKind::Interrupted {
                        return Err(error);
                    }
                }
            });
        }
        let mut child = command.spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while fs::read_to_string(domain.path.join("cgroup.procs"))
            .unwrap()
            .lines()
            .count()
            < 2
        {
            assert!(
                Instant::now() < deadline,
                "Descendant did not join owned domain"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        domain.terminate_domain().unwrap();
        domain
            .wait_empty(Instant::now() + Duration::from_secs(5))
            .unwrap();
        assert!(!child.wait().unwrap().success());
        domain
            .remove(Instant::now() + Duration::from_secs(5))
            .unwrap();
        assert!(!domain.path.exists());
        domain.terminate_domain().unwrap();
        domain.wait_empty(Instant::now()).unwrap();
    }
}
