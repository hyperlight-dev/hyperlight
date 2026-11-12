// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Standalone native probe for the Windows confinement unit tests.
//! Build explicitly with Rust 1.95 and set HYPERLIGHT_WINDOWS_CONFINEMENT_WORKER.

#![cfg(windows)]

use std::ffi::c_void;
use std::fs::OpenOptions;
use std::net::{SocketAddr, TcpStream};
use std::os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, OwnedHandle};
use std::process::{Command, Stdio};
use std::time::Duration;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn VirtualAlloc(
        address: *mut c_void,
        size: usize,
        allocation: u32,
        protect: u32,
    ) -> *mut c_void;
    fn VirtualFree(address: *mut c_void, size: usize, operation: u32) -> i32;
    fn GetCurrentProcess() -> *mut c_void;
    fn CloseHandle(handle: *mut c_void) -> i32;
    fn SetEvent(event: *mut c_void) -> i32;
    fn WaitForSingleObject(handle: *mut c_void, milliseconds: u32) -> u32;
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn OpenProcessToken(process: *mut c_void, access: u32, token: *mut *mut c_void) -> i32;
    fn GetTokenInformation(
        token: *mut c_void,
        class: u32,
        information: *mut c_void,
        size: u32,
        returned: *mut u32,
    ) -> i32;
}

#[link(name = "Firewallapi.dll", kind = "raw-dylib", modifiers = "+verbatim")]
unsafe extern "system" {
    fn NetworkIsolationDiagnoseConnectFailureAndGetInfo(server: *const u16, cause: *mut i32)
    -> u32;
}

#[link(
    name = "WinHvPlatform.dll",
    kind = "raw-dylib",
    modifiers = "+verbatim"
)]
unsafe extern "system" {
    fn WHvGetCapability(code: u32, buffer: *mut c_void, size: u32, written: *mut u32) -> i32;
    fn WHvCreatePartition(partition: *mut *mut c_void) -> i32;
    fn WHvDeletePartition(partition: *mut c_void) -> i32;
    fn WHvAcceptPartitionMigration(migration: *mut c_void, partition: *mut *mut c_void) -> i32;
    fn WHvSetupPartition(partition: *mut c_void) -> i32;
    fn WHvCreateVirtualProcessor(partition: *mut c_void, index: u32, flags: u32) -> i32;
    fn WHvDeleteVirtualProcessor(partition: *mut c_void, index: u32) -> i32;
}

fn deny_read(path: &str) -> bool {
    std::fs::read(path).is_err_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied)
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    let exit = match args.get(1).map(String::as_str) {
        Some("probe") => probe(&args),
        Some("network") => network_probe(&args[2]),
        Some("whp") => whp_probe(),
        Some("surrogate-mode") => {
            let value = std::env::var_os("HYPERLIGHT_MAX_SURROGATES");
            let expected = match args[2].as_str() {
                "single" => Some(std::ffi::OsString::from("0")),
                "absent" => None,
                _ => panic!("Unknown surrogate mode"),
            };
            if value == expected { 0 } else { 62 }
        }
        Some("whp-migration") => whp_migration_probe(&args),
        Some("connect") => {
            if TcpStream::connect_timeout(&args[2].parse().unwrap(), Duration::from_secs(2)).is_ok()
            {
                0
            } else {
                25
            }
        }
        Some("idle") => loop {
            std::thread::sleep(Duration::from_secs(1));
        },
        Some("tree") => {
            let child = Command::new(std::env::current_exe().unwrap())
                .arg("idle")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn();
            if child.is_err() {
                41
            } else {
                loop {
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
        }
        Some("child") => 42,
        _ => 99,
    };
    std::process::exit(exit);
}

fn whp_migration_probe(args: &[String]) -> i32 {
    if args.len() != 5 {
        return 70;
    }
    let handles: Vec<OwnedHandle> = args[2..]
        .iter()
        .map(|text| {
            let raw = text.parse::<usize>().unwrap() as *mut c_void;
            // SAFETY: The test supplies only these three owned inherited handles.
            unsafe { OwnedHandle::from_raw_handle(raw) }
        })
        .collect();
    let mut handles = handles.into_iter();
    let migration = handles.next().unwrap();
    let accepted = handles.next().unwrap();
    let completed = handles.next().unwrap();
    let confined = is_appcontainer_without_capabilities();
    eprintln!("MIGRATION destination: AppContainer with zero capabilities={confined}");
    if !confined {
        return 71;
    }
    // Keep the unchanged-token denial evidence beside the transfer result.
    whp_probe();
    let mut partition = std::ptr::null_mut();
    // SAFETY: migration is the inherited standard migration HANDLE, not a partition.
    let result = unsafe { WHvAcceptPartitionMigration(migration.as_raw_handle(), &mut partition) };
    eprintln!("MIGRATION destination: WHvAcceptPartitionMigration={result:#010x}");
    if result < 0 {
        return 72;
    }
    // Successful Accept consumes the HANDLE. Never close it a second time.
    let _ = migration.into_raw_handle();
    let outcome = (|| {
        // SAFETY: Both events are live handles from the explicit inheritance list.
        if unsafe { SetEvent(accepted.as_raw_handle()) } == 0 {
            return 73;
        }
        // SAFETY: Wait on the live completion event for a bounded period.
        let waited = unsafe { WaitForSingleObject(completed.as_raw_handle(), 8_000) };
        eprintln!("MIGRATION destination: source-complete wait={waited:#010x}");
        if waited != 0 {
            return 74;
        }
        // SAFETY: Accept returned this live partition. Source completion was signaled.
        let result = unsafe { WHvSetupPartition(partition) };
        eprintln!("MIGRATION destination: WHvSetupPartition={result:#010x}");
        if result < 0 {
            return 75;
        }
        // SAFETY: The migrated partition has processor count one and is set up.
        let result = unsafe { WHvCreateVirtualProcessor(partition, 0, 0) };
        eprintln!("MIGRATION destination: WHvCreateVirtualProcessor={result:#010x}");
        if result < 0 {
            return 76;
        }
        // SAFETY: VP zero was created above and has never been run.
        let result = unsafe { WHvDeleteVirtualProcessor(partition, 0) };
        eprintln!("MIGRATION destination: WHvDeleteVirtualProcessor={result:#010x}");
        if result < 0 { 77 } else { 0 }
    })();
    // SAFETY: This process owns the partition returned by successful Accept.
    let deleted = unsafe { WHvDeletePartition(partition) };
    eprintln!("MIGRATION destination: WHvDeletePartition={deleted:#010x}");
    if deleted < 0 { 78 } else { outcome }
}

fn whp_probe() -> i32 {
    let mut capability = [0u64; 32];
    let mut written = 0;
    // SAFETY: The aligned capability buffer and returned-size pointer are writable.
    let queried = unsafe {
        WHvGetCapability(
            0,
            capability.as_mut_ptr().cast(),
            std::mem::size_of_val(&capability) as u32,
            &mut written,
        )
    };
    let mut partition = std::ptr::null_mut();
    // SAFETY: The output pointer receives a new partition object owned by this probe.
    let created = unsafe { WHvCreatePartition(&mut partition) };
    let deleted = if created >= 0 {
        // SAFETY: Successful creation transferred this live partition object.
        Some(unsafe { WHvDeletePartition(partition) })
    } else {
        None
    };
    eprintln!(
        "WHP: query={queried:#010x} written={written} present={} create={created:#010x} delete={deleted:?}",
        capability[0] as u32,
    );
    if queried >= 0 && capability[0] as u32 != 0 && created >= 0 && deleted == Some(0) {
        0
    } else {
        61
    }
}

fn probe(args: &[String]) -> i32 {
    if args.len() != 6 {
        return 10;
    }
    if !is_appcontainer_without_capabilities() {
        return 19;
    }
    let executable = std::env::current_exe().unwrap();
    if std::fs::read(&executable).is_err() {
        return 20;
    }
    // Canonicalization can require access to protected ancestors of the image.
    if std::env::current_dir().ok().as_deref() != executable.parent() {
        return 21;
    }
    if std::fs::read("runtime.dat").ok().as_deref() != Some(b"immutable-runtime") {
        return 22;
    }
    if OpenOptions::new().write(true).open("runtime.dat").is_ok() {
        return 23;
    }
    if !deny_read(&args[2]) {
        return 11;
    }
    if !deny_read(&args[3]) {
        return 12;
    }
    if OpenOptions::new()
        .write(true)
        .open(std::env::current_exe().unwrap())
        .is_ok()
    {
        return 13;
    }
    if !deny_read(&args[5]) {
        return 24;
    }
    if std::env::vars_os().any(|(key, value)| {
        let allowed = key.to_str().is_some_and(|key| {
            key.eq_ignore_ascii_case("SystemRoot")
                || key.eq_ignore_ascii_case("LOCALAPPDATA")
                || (key.eq_ignore_ascii_case("HYPERLIGHT_MAX_SURROGATES") && value == "0")
                || ((key.eq_ignore_ascii_case("TEMP") || key.eq_ignore_ascii_case("TMP"))
                    && std::path::Path::new(&value) == std::path::Path::new(&args[4]))
        });
        if !allowed {
            eprintln!("Unexpected environment key: {key:?}");
        }
        !allowed
    }) {
        return 14;
    }
    if !Command::new(std::env::current_exe().unwrap())
        .arg("child")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .is_err_and(|error| matches!(error.raw_os_error(), Some(5 | 367)))
    {
        return 16;
    }
    // SAFETY: Request anonymous committed pages, above the test's 64 MiB job cap.
    let memory = unsafe { VirtualAlloc(std::ptr::null_mut(), 128 << 20, 0x3000, 0x04) };
    if !memory.is_null() {
        // SAFETY: memory is the base allocation returned immediately above.
        unsafe { VirtualFree(memory, 0, 0x8000) };
        return 18;
    }
    0
}

fn network_probe(server: &str) -> i32 {
    if !is_appcontainer_without_capabilities() {
        return 19;
    }
    let address: SocketAddr = server.parse().unwrap();
    let connection = TcpStream::connect_timeout(&address, Duration::from_secs(2));
    let server: Vec<u16> = address
        .ip()
        .to_string()
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut cause = 0;
    // SAFETY: A terminated IP literal and writable NETISO_ERROR_TYPE output.
    let result =
        unsafe { NetworkIsolationDiagnoseConnectFailureAndGetInfo(server.as_ptr(), &mut cause) };
    eprintln!(
        "Confined connection: {connection:?}; isolation diagnostic status={result}, cause={cause}"
    );
    if connection.is_err() && result == 0 && matches!(cause, 1..=3) {
        0
    } else {
        15
    }
}

fn is_appcontainer_without_capabilities() -> bool {
    let mut token = std::ptr::null_mut();
    // SAFETY: This opens the current process token for query only.
    if unsafe { OpenProcessToken(GetCurrentProcess(), 0x0008, &mut token) } == 0 {
        return false;
    }
    let mut is_container: u32 = 0;
    let mut returned = 0;
    // SAFETY: TokenIsAppContainer (29) writes a DWORD into a DWORD buffer.
    let container_ok = unsafe {
        GetTokenInformation(
            token,
            29,
            (&mut is_container as *mut u32).cast(),
            4,
            &mut returned,
        )
    } != 0
        && is_container == 1;
    let mut groups = [0usize; 128];
    // SAFETY: TOKEN_GROUPS starts with a DWORD count. Buffer is aligned and large
    // enough for an empty capability set. A larger response fails the probe.
    let capabilities_ok = unsafe {
        GetTokenInformation(
            token,
            30,
            groups.as_mut_ptr().cast(),
            size_of_val(&groups) as u32,
            &mut returned,
        )
    } != 0
        && groups[0] as u32 == 0;
    // SAFETY: OpenProcessToken transferred ownership to this function.
    unsafe { CloseHandle(token) };
    container_ok && capabilities_ok
}
