// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Mesh-provider process-placement example. See dev/process-isolation/QUICKSTART.md.

#[cfg(any(target_os = "linux", target_os = "windows"))]
mod isolation_bench_contracts;

#[cfg(any(target_os = "linux", target_os = "windows"))]
mod demo {
    use std::io::{BufRead, IsTerminal, Write};
    #[cfg(target_os = "linux")]
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::path::Path;
    use std::sync::Arc;
    use std::time::Duration;

    use hyperlight_host::process::{
        ControlResult, HostFunctionContract, HostFunctionProcess, Idempotency, MeshProcessProvider,
        ProcessControl, ProcessHostFunctions, ProcessOptions, ProcessProfile, ProcessReport,
        ProcessStartup, RequestedControl, SandboxHost,
    };
    use hyperlight_host::sandbox::snapshot::{OciTag, Snapshot};
    use hyperlight_host::{MultiUseSandbox, Result, SandboxBuilder, new_error};

    use super::isolation_bench_contracts::{ADD, ECHO, add, echo};

    const PID: HostFunctionContract<(), u32> =
        HostFunctionContract::new("ProcessId", Idempotency::Idempotent);
    const WINDOWS_VM_HOST_CONSENT: &str = "--allow-windows-vm-host";
    const NONINTERACTIVE: &str = "--noninteractive";
    const DETAILS: &str = "--details";

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Scenario {
        Local,
        FunctionWorker,
        VmHost,
        VmHostAndFunctionWorker,
        WorkerChildrenAllowed,
        WorkerChildrenBlocked,
    }

    impl Scenario {
        const ALL: [Self; 6] = [
            Self::Local,
            Self::FunctionWorker,
            Self::VmHost,
            Self::VmHostAndFunctionWorker,
            Self::WorkerChildrenAllowed,
            Self::WorkerChildrenBlocked,
        ];

        fn parse(name: &str) -> Result<Self> {
            match name {
                "local" => Ok(Self::Local),
                "function-worker" | "worker" => Ok(Self::FunctionWorker),
                "vm-host" | "sandbox" => Ok(Self::VmHost),
                "vm-host-and-function-worker" | "sandbox-worker" => {
                    Ok(Self::VmHostAndFunctionWorker)
                }
                "worker-children-allowed" | "children-allow" => Ok(Self::WorkerChildrenAllowed),
                "worker-children-blocked" | "children-deny" => Ok(Self::WorkerChildrenBlocked),
                _ => Err(new_error!(
                    "Mode must be local, function-worker, vm-host, \
                     vm-host-and-function-worker, worker-children-allowed or \
                     worker-children-blocked"
                )),
            }
        }

        fn name(self) -> &'static str {
            match self {
                Self::Local => "local",
                Self::FunctionWorker => "function-worker",
                Self::VmHost => "vm-host",
                Self::VmHostAndFunctionWorker => "vm-host-and-function-worker",
                Self::WorkerChildrenAllowed => "worker-children-allowed",
                Self::WorkerChildrenBlocked => "worker-children-blocked",
            }
        }

        fn dedicated_vm_host(self) -> bool {
            matches!(self, Self::VmHost | Self::VmHostAndFunctionWorker)
        }

        fn remote_functions(self) -> bool {
            matches!(
                self,
                Self::FunctionWorker
                    | Self::VmHostAndFunctionWorker
                    | Self::WorkerChildrenAllowed
                    | Self::WorkerChildrenBlocked
            )
        }

        fn child_policy(self) -> bool {
            matches!(
                self,
                Self::WorkerChildrenAllowed | Self::WorkerChildrenBlocked
            )
        }

        fn description(self) -> &'static str {
            match self {
                Self::Local => "VM and host functions run in the caller process",
                Self::FunctionWorker => {
                    "VM runs in the caller; host functions run in one confined function worker"
                }
                Self::VmHost => "VM and host functions share one dedicated sandbox host",
                Self::VmHostAndFunctionWorker => {
                    "VM runs in a dedicated sandbox host; host functions run in a separate confined function worker"
                }
                Self::WorkerChildrenAllowed => {
                    "VM runs in the caller; the confined function worker may create children"
                }
                Self::WorkerChildrenBlocked => {
                    "VM runs in the caller; the confined function worker cannot create children"
                }
            }
        }
    }

    fn profile(
        memory: u64,
        _quota: Duration,
        deny_network: bool,
        deny_children: bool,
        windows_vm_host: bool,
    ) -> ProcessProfile {
        let mut controls = vec![RequestedControl {
            control: ProcessControl::MemoryLimit(memory),
            required: true,
        }];
        #[cfg(target_os = "linux")]
        controls.push(RequestedControl {
            control: ProcessControl::CpuBudget {
                quota: _quota,
                period: Duration::from_millis(100),
            },
            required: true,
        });
        if deny_network && !windows_vm_host {
            controls.push(RequestedControl {
                control: ProcessControl::DenyNetwork,
                required: true,
            });
        }
        if deny_children {
            controls.push(RequestedControl {
                control: ProcessControl::DenyChildProcesses,
                required: true,
            });
        }
        let profile = ProcessProfile::new(controls);
        #[cfg(target_os = "windows")]
        let profile = profile
            .windows_cpu_rate_limit_percent(50)
            .expect("The fixed Windows CPU rate is valid");
        profile
    }

    fn options(name: &str, profile: ProcessProfile) -> ProcessOptions {
        ProcessOptions::for_provider(name, profile)
    }

    fn default_profile(allow_children: bool, windows_vm_host: bool) -> ProcessProfile {
        profile(
            512 << 20,
            Duration::from_millis(50),
            true,
            !allow_children,
            windows_vm_host,
        )
    }

    #[cfg(target_os = "linux")]
    fn process_cgroup(pid: i32) -> Result<String> {
        std::fs::read_to_string(format!("/proc/{pid}/cgroup"))?
            .lines()
            .find_map(|line| line.strip_prefix("0::").map(str::to_owned))
            .ok_or_else(|| new_error!("Process {pid} has no unified cgroup"))
    }

    fn check_independent_domains(
        scenario: Scenario,
        reports: &[hyperlight_host::process::ProcessReport],
    ) -> Result<()> {
        if scenario != Scenario::VmHostAndFunctionWorker {
            return Ok(());
        }
        if reports.len() != 2 {
            return Err(new_error!(
                "sandbox-worker must report two simultaneous native domains"
            ));
        }
        #[cfg(target_os = "linux")]
        {
            let left = process_cgroup(reports[0].root_process_id)?;
            let right = process_cgroup(reports[1].root_process_id)?;
            if left == right {
                return Err(new_error!(
                    "sandbox-worker native roles share one cgroup domain"
                ));
            }
        }
        let sandbox = reports
            .iter()
            .find(|report| {
                report.role == hyperlight_host::process::program::ProgramRole::SandboxHost
            })
            .ok_or_else(|| new_error!("sandbox-worker has no sandbox report"))?;
        let worker = reports
            .iter()
            .find(|report| {
                report.role == hyperlight_host::process::program::ProgramRole::FunctionWorker
            })
            .ok_or_else(|| new_error!("sandbox-worker has no worker report"))?;
        if sandbox.root_process_id == worker.root_process_id {
            return Err(new_error!("sandbox-worker reports share one root process"));
        }
        #[cfg(target_os = "linux")]
        let effective = |report: &hyperlight_host::process::ProcessReport| {
            report
                .controls
                .iter()
                .filter_map(|outcome| match &outcome.result {
                    hyperlight_host::process::ControlResult::Applied { effective, .. } => {
                        Some(effective.clone())
                    }
                    hyperlight_host::process::ControlResult::NotApplied { .. } => None,
                })
                .collect::<Vec<_>>()
        };
        #[cfg(target_os = "linux")]
        let sandbox_controls = effective(sandbox);
        #[cfg(target_os = "linux")]
        let worker_controls = effective(worker);
        #[cfg(target_os = "linux")]
        let sandbox_expected = [
            ProcessControl::MemoryLimit(384 << 20),
            ProcessControl::CpuBudget {
                quota: Duration::from_millis(60),
                period: Duration::from_millis(100),
            },
            ProcessControl::DenyNetwork,
            ProcessControl::DenyChildProcesses,
        ];
        #[cfg(target_os = "linux")]
        let worker_expected = [
            ProcessControl::MemoryLimit(192 << 20),
            ProcessControl::CpuBudget {
                quota: Duration::from_millis(30),
                period: Duration::from_millis(100),
            },
        ];
        #[cfg(target_os = "linux")]
        if !sandbox_expected
            .iter()
            .all(|control| sandbox_controls.contains(control))
            || !worker_expected
                .iter()
                .all(|control| worker_controls.contains(control))
            || worker_controls.contains(&ProcessControl::DenyNetwork)
            || worker_controls.contains(&ProcessControl::DenyChildProcesses)
        {
            return Err(new_error!(
                "sandbox-worker domains do not have distinct resource, network and child policies"
            ));
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn domain_memberships(
        reports: &[hyperlight_host::process::ProcessReport],
    ) -> Result<
        Vec<(
            hyperlight_host::process::program::ProgramRole,
            String,
            i32,
            String,
        )>,
    > {
        reports
            .iter()
            .map(|report| {
                Ok((
                    report.role,
                    report.name.clone(),
                    report.root_process_id,
                    process_cgroup(report.root_process_id)?,
                ))
            })
            .collect()
    }

    #[cfg(not(target_os = "linux"))]
    fn domain_memberships(_reports: &[hyperlight_host::process::ProcessReport]) -> Result<Vec<()>> {
        Ok(Vec::new())
    }

    #[cfg(target_os = "linux")]
    fn check_domain_membership_unchanged(
        before: &[(
            hyperlight_host::process::program::ProgramRole,
            String,
            i32,
            String,
        )],
        after: &[hyperlight_host::process::ProcessReport],
    ) -> Result<()> {
        if before.len() != after.len() {
            return Err(new_error!("Native process count changed unexpectedly"));
        }
        for (role, name, root_process_id, cgroup) in before {
            let current = after
                .iter()
                .find(|report| report.role == *role && report.name == *name)
                .ok_or_else(|| new_error!("Native process role changed"))?;
            if current.root_process_id != *root_process_id
                || process_cgroup(current.root_process_id)? != *cgroup
            {
                return Err(new_error!("Native process moved between ownership domains"));
            }
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn check_domain_membership_unchanged(
        _before: &[()],
        _after: &[hyperlight_host::process::ProcessReport],
    ) -> Result<()> {
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn qualify_worker_recovery(
        sandbox: &mut MultiUseSandbox,
        scenario: Scenario,
        original: Vec<hyperlight_host::process::ProcessReport>,
    ) -> Result<Vec<hyperlight_host::process::ProcessReport>> {
        if scenario != Scenario::VmHostAndFunctionWorker {
            return Ok(original);
        }
        let worker = original
            .iter()
            .find(|report| {
                report.role == hyperlight_host::process::program::ProgramRole::FunctionWorker
            })
            .ok_or_else(|| new_error!("sandbox-worker has no worker report"))?;
        let old_domain = Path::new("/sys/fs/cgroup")
            .join(process_cgroup(worker.root_process_id)?.trim_start_matches('/'));
        // SAFETY: pidfd_open takes a positive reported process ID and zero flags.
        let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, worker.root_process_id, 0) };
        if descriptor < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: pidfd_open returned a fresh descriptor with sole ownership here.
        let pidfd = unsafe { OwnedFd::from_raw_fd(descriptor as i32) };
        // SAFETY: the live pidfd pins the process identity. SIGKILL needs no siginfo.
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                pidfd.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if sandbox.call::<i32>("Add", (20, 22))? != 42 {
            return Err(new_error!("Recovered worker changed callback behavior"));
        }
        let recovered = sandbox.process_reports();
        check_independent_domains(scenario, &recovered)?;
        for current in &recovered {
            let previous = original
                .iter()
                .find(|report| report.role == current.role && report.name == current.name)
                .ok_or_else(|| new_error!("Recovered native process role changed"))?;
            if current.role == hyperlight_host::process::program::ProgramRole::FunctionWorker {
                if current.root_process_id == previous.root_process_id {
                    return Err(new_error!("Killed function worker was not replaced"));
                }
            } else if current.root_process_id != previous.root_process_id {
                return Err(new_error!(
                    "Function-worker recovery replaced the sandbox host"
                ));
            }
        }
        if old_domain.exists() {
            return Err(new_error!("Retired worker cgroup was not removed"));
        }
        println!("sandbox-worker: isolated worker recovery and retired-domain cleanup passed");
        Ok(recovered)
    }

    #[cfg(not(target_os = "linux"))]
    fn qualify_worker_recovery(
        _sandbox: &mut MultiUseSandbox,
        _scenario: Scenario,
        original: Vec<hyperlight_host::process::ProcessReport>,
    ) -> Result<Vec<hyperlight_host::process::ProcessReport>> {
        Ok(original)
    }

    fn check_calls(sandbox: &mut MultiUseSandbox, child_policy: bool) -> Result<()> {
        let result = sandbox.call::<i32>("Add", (17, 25))?;
        if result != 42 {
            return Err(new_error!("Placement changed Add = 42 to {result}"));
        }
        if !child_policy
            && sandbox.call::<String>("RoundTripHostString", "hello".to_owned())? != "hello"
        {
            return Err(new_error!("Placement changed the string callback result"));
        }
        Ok(())
    }

    fn create_output(path: &Path) -> Result<()> {
        std::fs::create_dir(path).map_err(|error| match error.kind() {
            std::io::ErrorKind::AlreadyExists => new_error!(
                "Output directory {} already exists. Preserve or rename it, then choose a new path",
                path.display()
            ),
            std::io::ErrorKind::NotFound => new_error!(
                "Output parent for {} does not exist. Create only its parent directory first",
                path.display()
            ),
            _ => new_error!("Creating output directory {}: {error}", path.display()),
        })
    }

    #[cfg(target_os = "windows")]
    fn validate_output_path(path: &Path) -> Result<()> {
        const MAX_PATH_WITHOUT_NUL: usize = 259;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let name = path
            .file_name()
            .ok_or_else(|| new_error!("Output directory needs a final path component"))?;
        let absolute = std::fs::canonicalize(parent)
            .map_err(|error| {
                new_error!("Output parent {} is unavailable: {error}", parent.display())
            })?
            .join(name);
        let blob = absolute
            .join("snapshot")
            .join("blobs")
            .join("sha256")
            .join("0".repeat(64));
        let root_units = windows_legacy_path_units(&absolute);
        let blob_units = windows_legacy_path_units(&blob);
        if blob_units > MAX_PATH_WITHOUT_NUL {
            let suffix_units = blob_units - root_units;
            let maximum = MAX_PATH_WITHOUT_NUL - suffix_units;
            return Err(new_error!(
                "Windows output directory is {root_units} UTF-16 units after resolution; \
                 the maximum is {maximum} because OCI snapshot blob paths add {suffix_units}. \
                 Choose a shorter parent or output name"
            ));
        }
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn windows_legacy_path_units(path: &Path) -> usize {
        use std::os::windows::ffi::OsStrExt;
        use std::path::{Component, Prefix};

        let units = path.as_os_str().encode_wide().count();
        match path.components().next() {
            Some(Component::Prefix(prefix)) => match prefix.kind() {
                Prefix::VerbatimDisk(_) => units - 4,
                Prefix::VerbatimUNC(_, _) => units - 6,
                _ => units,
            },
            _ => units,
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn validate_output_path(_: &Path) -> Result<()> {
        Ok(())
    }

    fn print_reports(label: &str, reports: &[ProcessReport]) {
        println!("{label}:");
        if reports.is_empty() {
            println!("  No additional native processes. The VM and functions use the caller.");
            return;
        }
        for report in reports {
            println!(
                "  {:?} '{}' PID {}",
                report.role, report.name, report.root_process_id
            );
            println!("    Boundary: {}", report.effective_isolation());
            if let Some(percent) = report.windows_cpu_rate_limit_percent() {
                println!(
                    "    Applied Windows CPU rate: {percent}% of aggregate host processor capacity"
                );
            }
            for control in &report.controls {
                match &control.result {
                    ControlResult::Applied {
                        effective,
                        mechanism,
                    } => println!("    Applied {effective:?}: {mechanism}"),
                    ControlResult::NotApplied { reason } => {
                        println!("    Not applied {:?}: {reason}", control.requested.control)
                    }
                }
            }
        }
    }

    fn human_size(bytes: u64) -> String {
        if bytes.is_multiple_of(1 << 20) {
            format!("{} MiB", bytes >> 20)
        } else {
            format!("{bytes} bytes")
        }
    }

    fn control_explanation(control: &ProcessControl) -> String {
        match control {
            ProcessControl::MemoryLimit(bytes) => {
                #[cfg(target_os = "linux")]
                return format!(
                    "Memory is capped at {} by the process cgroup.",
                    human_size(*bytes)
                );
                #[cfg(target_os = "windows")]
                return format!(
                    "Memory is capped at {} by a Windows Job object.",
                    human_size(*bytes)
                );
            }
            ProcessControl::CpuBudget { quota, period } => format!(
                "CPU time is capped at {} ms in each {} ms period by the process cgroup.",
                quota.as_millis(),
                period.as_millis()
            ),
            ProcessControl::DenyNetwork => {
                #[cfg(target_os = "linux")]
                return "Network access is blocked by a private network namespace.".to_owned();
                #[cfg(target_os = "windows")]
                return "Network access is blocked because the AppContainer has no network capability."
                    .to_owned();
            }
            ProcessControl::DenyChildProcesses => {
                #[cfg(target_os = "linux")]
                return "New processes are blocked by a seccomp rule. Threads remain available."
                    .to_owned();
                #[cfg(target_os = "windows")]
                return "New processes are blocked by the Windows Job child-process policy."
                    .to_owned();
            }
        }
    }

    fn role_name(report: &ProcessReport) -> &'static str {
        match report.role {
            hyperlight_host::process::program::ProgramRole::SandboxHost => "VM sandbox host",
            hyperlight_host::process::program::ProgramRole::FunctionWorker => "function worker",
        }
    }

    fn process_access_explanation(scenario: Scenario, report: &ProcessReport) -> Vec<String> {
        let mut lines = Vec::new();
        match report.role {
            hyperlight_host::process::program::ProgramRole::FunctionWorker => {
                lines.push(
                    "Receives only the declared host-function calls and their serialized values."
                        .to_owned(),
                );
                #[cfg(target_os = "linux")]
                lines.push(
                    "Sees its provider-staged program and runtime files. A private mount namespace and Landlock rules block paths outside the allowlist."
                        .to_owned(),
                );
                #[cfg(target_os = "windows")]
                lines.push(
                    "Runs in AppContainer with provider-staged files. It cannot browse the controller's ordinary filesystem."
                        .to_owned(),
                );
            }
            hyperlight_host::process::program::ProgramRole::SandboxHost => {
                lines.push(
                    "Owns the VM and receives only the declared guest and host-function endpoints."
                        .to_owned(),
                );
                #[cfg(target_os = "linux")]
                lines.push(
                    "Sees provider-staged runtime files and the delegated hypervisor device. A private mount namespace and Landlock rules block paths outside the allowlist."
                        .to_owned(),
                );
                #[cfg(target_os = "windows")]
                lines.push(
                    "Runs as an ordinary non-elevated process so WHP remains available. It is not an AppContainer filesystem or network boundary."
                        .to_owned(),
                );
                if scenario == Scenario::VmHost {
                    lines.push(
                        "The host functions share this process and therefore share its access."
                            .to_owned(),
                    );
                }
            }
        }
        for outcome in &report.controls {
            if matches!(outcome.result, ControlResult::Applied { .. }) {
                lines.push(control_explanation(&outcome.requested.control));
            }
        }
        #[cfg(target_os = "windows")]
        if let Some(percent) = report.windows_cpu_rate_limit_percent() {
            lines.push(format!(
                "CPU use is capped at {percent}% of aggregate host capacity by the Windows Job."
            ));
        }
        lines
    }

    fn inspection_commands(reports: &[ProcessReport]) -> Vec<String> {
        let pids = reports
            .iter()
            .map(|report| report.root_process_id.to_string())
            .collect::<Vec<_>>();
        #[cfg(target_os = "linux")]
        {
            if pids.is_empty() {
                return vec![format!("ps -o pid,ppid,stat,cmd -p {}", std::process::id())];
            }
            let joined = pids.join(",");
            vec![
                format!("ps -o pid,ppid,stat,cmd -p {joined}"),
                format!("for p in {}; do cat /proc/$p/cgroup; done", pids.join(" ")),
                format!("for p in {}; do ls -l /proc/$p/ns; done", pids.join(" ")),
            ]
        }
        #[cfg(target_os = "windows")]
        {
            if pids.is_empty() {
                return vec![format!(
                    "Get-Process -Id {} | Format-List Id,ProcessName,Path",
                    std::process::id()
                )];
            }
            vec![format!(
                "Get-Process -Id {} | Format-Table Id,ProcessName,Path",
                pids.join(",")
            )]
        }
    }

    fn print_demo_topology(scenario: Scenario, reports: &[ProcessReport], details: bool) {
        let controller = std::process::id();
        println!("  Controller PID: {controller}");
        if reports.is_empty() {
            println!("  VM: controller PID {controller}");
            println!("  Host functions: controller PID {controller}");
            println!("  Access: the VM remains the guest security boundary.");
            println!(
                "  Native limits: no per-role limits. The controller keeps its ambient access. An outer launcher may bound the whole application."
            );
        } else {
            for report in reports {
                println!(
                    "  {} PID {}: launched and owned by controller PID {}",
                    role_name(report),
                    report.root_process_id,
                    controller
                );
                for line in process_access_explanation(scenario, report) {
                    println!("    {line}");
                }
                if details {
                    println!("    Technical boundary: {}", report.effective_isolation());
                    for control in &report.controls {
                        match &control.result {
                            ControlResult::Applied {
                                effective,
                                mechanism,
                            } => println!("    Detail: {effective:?} via {mechanism}"),
                            ControlResult::NotApplied { reason } => println!(
                                "    Detail: {:?} was not applied: {reason}",
                                control.requested.control
                            ),
                        }
                    }
                }
            }
        }
        println!("  Inspect from a second terminal:");
        for command in inspection_commands(reports) {
            println!("    {command}");
        }
    }

    fn wait_for_inspection<R: BufRead, W: Write>(
        noninteractive: bool,
        stdin_is_terminal: bool,
        input: &mut R,
        output: &mut W,
    ) -> Result<()> {
        if noninteractive {
            return Ok(());
        }
        if !stdin_is_terminal {
            return Err(new_error!(
                "Interactive demo input is not a terminal. Run with {NONINTERACTIVE} for CI or redirected input"
            ));
        }
        write!(output, "  Press Enter to stop this mode and continue... ")?;
        output.flush()?;
        let mut line = String::new();
        if input.read_line(&mut line)? == 0 {
            return Err(new_error!(
                "Interactive demo input closed before Enter. Run with {NONINTERACTIVE} when no operator is present"
            ));
        }
        writeln!(output)?;
        Ok(())
    }

    fn validate_consent(scenario: Scenario, consent: bool) -> Result<()> {
        if cfg!(target_os = "windows") && scenario.dedicated_vm_host() && !consent {
            return Err(new_error!(
                "{} requires {} because its VM host runs outside AppContainer. \
                 That host has no AppContainer filesystem or network isolation",
                scenario.name(),
                WINDOWS_VM_HOST_CONSENT
            ));
        }
        if consent && (!cfg!(target_os = "windows") || !scenario.dedicated_vm_host()) {
            return Err(new_error!(
                "{} is valid only for Windows vm-host modes",
                WINDOWS_VM_HOST_CONSENT
            ));
        }
        Ok(())
    }

    pub fn run_process(startup: ProcessStartup) -> Result<()> {
        let role = startup.role()?;
        let name = startup.name()?;
        let mut functions = ProcessHostFunctions::default();
        match (role, name.as_str()) {
            (hyperlight_host::process::program::ProgramRole::FunctionWorker, "functions") => {
                functions.bind(ADD, add)?;
                functions.bind(ECHO, echo)?;
                functions.run(startup)
            }
            (
                hyperlight_host::process::program::ProgramRole::FunctionWorker,
                "worker-children-allowed" | "worker-children-blocked",
            ) => {
                let allow_children = name == "worker-children-allowed";
                functions.bind(ADD, move |a, b| {
                    let check = move || -> std::result::Result<(), i32> {
                        let result = std::process::Command::new(
                            std::env::current_exe().expect("Current executable must be available"),
                        )
                        .arg("--policy-child")
                        .status();
                        if allow_children {
                            assert!(result.expect("Child creation must succeed").success());
                            Ok(())
                        } else {
                            child_creation_denied(result)
                        }
                    };
                    if let Err(code) = check() {
                        return code;
                    }
                    if let Err(code) = std::thread::spawn(check)
                        .join()
                        .expect("Confined Rust thread must complete")
                    {
                        return code;
                    }
                    a + b
                })?;
                functions.bind(PID, std::process::id)?;
                functions.run(startup)
            }
            (hyperlight_host::process::program::ProgramRole::SandboxHost, "vm-host-local") => {
                functions.bind(ADD, add)?;
                functions.bind(ECHO, echo)?;
                SandboxHost::new(functions).run(startup)
            }
            (hyperlight_host::process::program::ProgramRole::SandboxHost, "vm-host-remote") => {
                SandboxHost::new(functions).run(startup)
            }
            _ => Err(new_error!(
                "Unknown Mesh process role '{role:?}' for '{name}'"
            )),
        }
    }

    pub fn run_controller() -> Result<()> {
        let args: Vec<_> = std::env::args_os().skip(1).collect();
        if args == ["--policy-child"] {
            return Ok(());
        }
        if args == ["--help"] || args == ["-h"] {
            println!("{}", help_text());
            return Ok(());
        }
        if args.first().is_some_and(|argument| argument == "demo") {
            return run_demo(&args[1..]);
        }
        if args.first().is_some_and(|argument| argument == "qualify") {
            return run_qualification(&args[1..]);
        }
        run_qualification(&args)
    }

    fn parse_qualification_args(args: &[std::ffi::OsString]) -> Result<(Scenario, &Path, &Path)> {
        if !(args.len() == 3 || args.len() == 4) {
            return Err(new_error!(
                "Usage: process_placement qualify MODE GUEST NEW_OUTPUT_DIRECTORY \
                 [--allow-windows-vm-host]"
            ));
        }
        let scenario = Scenario::parse(
            args[0]
                .to_str()
                .ok_or_else(|| new_error!("Invalid placement mode"))?,
        )?;
        let consent = args
            .get(3)
            .is_some_and(|arg| arg == WINDOWS_VM_HOST_CONSENT);
        if args.len() == 4 && !consent {
            return Err(new_error!("Unknown option '{}'", args[3].to_string_lossy()));
        }
        validate_consent(scenario, consent)?;
        Ok((scenario, Path::new(&args[1]), Path::new(&args[2])))
    }

    fn build_sandbox(
        scenario: Scenario,
        guest: &Path,
    ) -> Result<(MultiUseSandbox, Option<MeshProcessProvider>)> {
        let dedicated = scenario.dedicated_vm_host();
        let remote = scenario.remote_functions();
        let child_policy = scenario.child_policy();
        let provider = (dedicated || remote)
            .then(MeshProcessProvider::discover)
            .transpose()?;
        let mut builder = SandboxBuilder::from_file(guest);
        if let Some(provider) = &provider {
            builder = builder.mesh_process_provider(provider.clone());
        }
        if remote {
            let worker_name = match scenario {
                Scenario::WorkerChildrenAllowed => "worker-children-allowed",
                Scenario::WorkerChildrenBlocked => "worker-children-blocked",
                _ => "functions",
            };
            let worker_profile = if scenario == Scenario::VmHostAndFunctionWorker {
                profile(192 << 20, Duration::from_millis(30), false, false, false)
            } else {
                default_profile(scenario == Scenario::WorkerChildrenAllowed, false)
            };
            let mut worker =
                HostFunctionProcess::new(options(worker_name, worker_profile)).function(ADD);
            worker = if child_policy {
                worker.function(PID)
            } else {
                worker.function(ECHO)
            };
            builder = builder.host_function_process(worker);
        } else if !dedicated {
            builder = builder
                .host_function("HostAdd", add)
                .host_function("HostEchoString", echo);
        }
        if dedicated {
            let sandbox_profile = if scenario == Scenario::VmHostAndFunctionWorker {
                profile(
                    384 << 20,
                    Duration::from_millis(60),
                    true,
                    true,
                    cfg!(target_os = "windows"),
                )
            } else {
                default_profile(false, cfg!(target_os = "windows"))
            };
            let options = options(
                if remote {
                    "vm-host-remote"
                } else {
                    "vm-host-local"
                },
                sandbox_profile,
            );
            #[cfg(target_os = "windows")]
            {
                builder = builder.windows_vm_host_process(options);
            }
            #[cfg(target_os = "linux")]
            {
                builder = builder.sandbox_process(options);
            }
            if !remote {
                builder = builder
                    .sandbox_host_function(ADD)
                    .sandbox_host_function(ECHO);
            }
        }
        Ok((builder.build()?, provider))
    }

    fn run_demo(args: &[std::ffi::OsString]) -> Result<()> {
        let mut guest = None;
        let mut noninteractive = false;
        let mut details = false;
        let mut consent = false;
        for argument in args {
            match argument.to_str() {
                Some(NONINTERACTIVE) => noninteractive = true,
                Some(DETAILS) | Some("--verbose") => details = true,
                Some(WINDOWS_VM_HOST_CONSENT) => consent = true,
                Some(value) if value.starts_with('-') => {
                    return Err(new_error!("Unknown demo option '{value}'"));
                }
                Some(_) if guest.is_none() => guest = Some(Path::new(argument)),
                Some(value) => return Err(new_error!("Unexpected demo argument '{value}'")),
                None => return Err(new_error!("Demo arguments must be valid Unicode")),
            }
        }
        let guest = guest.ok_or_else(|| {
            new_error!(
                "Usage: process_placement demo GUEST [{NONINTERACTIVE}] [{DETAILS}] [{WINDOWS_VM_HOST_CONSENT}]"
            )
        })?;
        if consent && !cfg!(target_os = "windows") {
            return Err(new_error!(
                "{WINDOWS_VM_HOST_CONSENT} is valid only on Windows"
            ));
        }
        if cfg!(target_os = "windows") && !consent {
            return Err(new_error!(
                "The six-mode Windows demo requires {WINDOWS_VM_HOST_CONSENT} because two modes use a WHP-compatible VM host outside AppContainer"
            ));
        }
        if !noninteractive && !std::io::stdin().is_terminal() {
            return Err(new_error!(
                "Interactive demo input is not a terminal. Run with {NONINTERACTIVE} for CI or redirected input"
            ));
        }
        let guest = std::fs::canonicalize(guest).map_err(|error| {
            new_error!(
                "Guest binary {} is unavailable: {error}. Build the release guest and pass its existing path",
                guest.display()
            )
        })?;
        println!();
        println!("Hyperlight process placement demo");
        println!(
            "Six modes. A small live call set per mode. Native processes stay alive for inspection."
        );
        for (index, scenario) in Scenario::ALL.into_iter().enumerate() {
            println!();
            println!("[{}/6] {}", index + 1, scenario.name().to_ascii_uppercase());
            println!("{}", scenario.description());
            let (mut sandbox, _) = build_sandbox(scenario, &guest)?;
            check_calls(&mut sandbox, scenario.child_policy())?;
            let reports = sandbox.process_reports();
            check_independent_domains(scenario, &reports)?;
            println!("  PASS Add(17, 25) = 42");
            print_demo_topology(scenario, &reports, details);
            wait_for_inspection(
                noninteractive,
                std::io::stdin().is_terminal(),
                &mut std::io::stdin().lock(),
                &mut std::io::stdout().lock(),
            )?;
            sandbox.shutdown()?;
            drop(sandbox);
            verify_processes_stopped(&reports)?;
            println!("  PASS shutdown and native-process cleanup");
        }
        println!();
        println!("PASS all six process placement modes");
        Ok(())
    }

    fn run_qualification(args: &[std::ffi::OsString]) -> Result<()> {
        let (scenario, guest_input, output) = parse_qualification_args(args)?;
        let guest = std::fs::canonicalize(guest_input).map_err(|error| {
            new_error!(
                "Guest binary {} is unavailable: {error}. Build the guest and pass its existing path",
                guest_input.display()
            )
        })?;
        validate_output_path(output)?;
        create_output(output)?;
        println!("Mode: {}. {}", scenario.name(), scenario.description());
        if cfg!(target_os = "windows") && scenario == Scenario::VmHost {
            println!(
                "Security note: co-located host functions share the VM host. They do not have AppContainer filesystem or network isolation."
            );
        }
        let dedicated = scenario.dedicated_vm_host();
        let remote = scenario.remote_functions();
        let child_policy = scenario.child_policy();
        let (mut sandbox, provider) = build_sandbox(scenario, &guest)?;
        check_calls(&mut sandbox, child_policy)?;
        let original_reports = sandbox.process_reports();
        print_reports("Original process report", &original_reports);
        check_independent_domains(scenario, &original_reports)?;
        let original_reports = qualify_worker_recovery(&mut sandbox, scenario, original_reports)?;
        if scenario == Scenario::VmHostAndFunctionWorker {
            print_reports("Recovered process report", &original_reports);
        }
        let original_memberships = domain_memberships(&original_reports)?;
        let state = sandbox.call::<i32>("GetStatic", ())?;
        let snapshot = sandbox.snapshot()?;
        if sandbox.call::<i32>("AddToStatic", 7)? != state + 7 {
            return Err(new_error!("Guest mutation failed"));
        }
        sandbox.restore(snapshot.clone())?;
        if sandbox.call::<i32>("GetStatic", ())? != state {
            return Err(new_error!("Guest restore failed"));
        }
        check_domain_membership_unchanged(&original_memberships, &sandbox.process_reports())?;
        let layout = output.join("snapshot");
        let tag = OciTag::new("placement")?;
        let digest = match &provider {
            Some(provider) => snapshot.save_with_process_provider(&layout, &tag, provider)?,
            None => snapshot.save(&layout, &tag)?,
        };
        sandbox.shutdown()?;
        drop(sandbox);
        verify_processes_stopped(&original_reports)?;
        drop(snapshot);
        let loaded = Arc::new(Snapshot::checked_load(&layout, digest.clone())?);
        let mut builder = SandboxBuilder::from_snapshot(loaded);
        if dedicated || remote {
            builder =
                builder.mesh_process_provider(MeshProcessProvider::discover_for_snapshot(&layout)?);
            #[cfg(target_os = "windows")]
            if dedicated {
                builder = builder.allow_windows_vm_host();
            }
        } else {
            builder = builder
                .host_function("HostAdd", add)
                .host_function("HostEchoString", echo);
        }
        let mut fresh = builder.build()?;
        check_calls(&mut fresh, child_policy)?;
        if fresh.call::<i32>("GetStatic", ())? != state {
            return Err(new_error!("OCI guest state differs"));
        }
        let reconstructed_reports = fresh.process_reports();
        print_reports("Reconstructed process report", &reconstructed_reports);
        check_independent_domains(scenario, &reconstructed_reports)?;
        fresh.shutdown()?;
        drop(fresh);
        verify_processes_stopped(&reconstructed_reports)?;
        println!(
            "PASS: {}. Callbacks, Add = 42, guest restore, OCI reconstruction and checked process cleanup succeeded.",
            scenario.name()
        );
        println!("OCI layout: {}\nManifest: {digest}", layout.display());
        Ok(())
    }

    fn help_text() -> &'static str {
        "Usage:\n\
  process_placement demo GUEST [--noninteractive] [--details] [--allow-windows-vm-host]\n\
  process_placement qualify MODE GUEST NEW_OUTPUT_DIRECTORY [--allow-windows-vm-host]\n\
  process_placement MODE GUEST NEW_OUTPUT_DIRECTORY [--allow-windows-vm-host]\n\
\n\
Modes:\n\
  local                         VM and host functions use the caller process\n\
  function-worker               VM uses the caller; functions use one confined worker\n\
  vm-host                       VM and host functions share one dedicated VM host\n\
  vm-host-and-function-worker   VM host and confined function worker are separate\n\
  worker-children-allowed       Confined function worker may create child processes\n\
  worker-children-blocked       Confined function worker cannot create child processes\n\
\n\
The demo runs all six modes and pauses while each topology is live. Use\n\
--noninteractive for CI or redirected input. Qualification retains snapshot,\n\
reconstruction, recovery and cleanup checks. Its output directory must not exist.\n\
Windows demos and VM-host qualification require --allow-windows-vm-host because\n\
the VM host runs outside AppContainer."
    }

    fn verify_processes_stopped(reports: &[ProcessReport]) -> Result<()> {
        for report in reports {
            if process_exists(report.root_process_id)? {
                return Err(new_error!(
                    "Process cleanup left PID {} running for '{}'",
                    report.root_process_id,
                    report.name
                ));
            }
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn process_exists(pid: i32) -> Result<bool> {
        let stat = Path::new("/proc").join(pid.to_string()).join("stat");
        match std::fs::read_to_string(stat) {
            Ok(contents) => {
                let state = contents
                    .rsplit_once(") ")
                    .and_then(|(_, suffix)| suffix.chars().next())
                    .ok_or_else(|| new_error!("Malformed process status for PID {pid}"))?;
                Ok(state != 'Z')
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(new_error!("Checking PID {pid}: {error}")),
        }
    }

    #[cfg(target_os = "windows")]
    fn process_exists(pid: i32) -> Result<bool> {
        use windows::Win32::Foundation::{CloseHandle, E_INVALIDARG, WAIT_OBJECT_0, WAIT_TIMEOUT};
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
            WaitForSingleObject,
        };

        // SAFETY: the queried handle is valid until it is closed below.
        unsafe {
            let handle = match OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                false,
                pid as u32,
            ) {
                Ok(handle) => handle,
                Err(error) if error.code() == E_INVALIDARG => return Ok(false),
                Err(error) => return Err(new_error!("Opening PID {pid}: {error}")),
            };
            let wait = WaitForSingleObject(handle, 0);
            CloseHandle(handle).map_err(|error| new_error!("Closing PID {pid}: {error}"))?;
            if wait == WAIT_TIMEOUT {
                Ok(true)
            } else if wait == WAIT_OBJECT_0 {
                Ok(false)
            } else {
                Err(new_error!("Waiting for PID {pid} returned {wait:?}"))
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn child_creation_denied(
        result: std::io::Result<std::process::ExitStatus>,
    ) -> std::result::Result<(), i32> {
        const ERROR_CHILD_PROCESS_BLOCKED: i32 = 367;
        const ERROR_NOT_ENOUGH_QUOTA: i32 = 1816;
        match result {
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(ERROR_CHILD_PROCESS_BLOCKED | ERROR_NOT_ENOUGH_QUOTA)
                ) =>
            {
                Ok(())
            }
            Err(error) => Err(negative_diagnostic(error.raw_os_error())),
            Ok(_) => Err(i32::MAX),
        }
    }

    #[cfg(target_os = "linux")]
    fn child_creation_denied(
        result: std::io::Result<std::process::ExitStatus>,
    ) -> std::result::Result<(), i32> {
        match result {
            Err(error) if error.raw_os_error() == Some(libc::EPERM) => Ok(()),
            Err(error) => Err(negative_diagnostic(error.raw_os_error())),
            Ok(_) => Err(i32::MAX),
        }
    }

    fn negative_diagnostic(code: Option<i32>) -> i32 {
        let code = code.unwrap_or(i32::MAX);
        if code == i32::MIN {
            i32::MIN
        } else {
            -code.abs()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn six_plain_english_modes_are_independent() {
            for (name, expected) in [
                ("local", Scenario::Local),
                ("function-worker", Scenario::FunctionWorker),
                ("vm-host", Scenario::VmHost),
                (
                    "vm-host-and-function-worker",
                    Scenario::VmHostAndFunctionWorker,
                ),
                ("worker-children-allowed", Scenario::WorkerChildrenAllowed),
                ("worker-children-blocked", Scenario::WorkerChildrenBlocked),
            ] {
                assert_eq!(Scenario::parse(name).unwrap(), expected);
            }
            assert!(Scenario::parse("unknown").is_err());
        }

        #[test]
        fn help_lists_all_modes_and_windows_consent() {
            let help = help_text();
            for mode in [
                "local",
                "function-worker",
                "vm-host",
                "vm-host-and-function-worker",
                "worker-children-allowed",
                "worker-children-blocked",
            ] {
                assert!(help.contains(mode));
            }
            assert!(help.contains("--allow-windows-vm-host"));
            assert!(help.contains("demo GUEST"));
            assert!(help.contains("qualify MODE"));
            assert!(help.contains("--noninteractive"));
        }

        #[test]
        fn demo_dispatch_contains_all_six_modes() {
            assert_eq!(Scenario::ALL.len(), 6);
            for scenario in Scenario::ALL {
                assert_eq!(Scenario::parse(scenario.name()).unwrap(), scenario);
            }
        }

        #[test]
        fn noninteractive_pause_returns_without_input() {
            let mut input = std::io::Cursor::new(Vec::<u8>::new());
            let mut output = Vec::new();
            wait_for_inspection(true, false, &mut input, &mut output).unwrap();
            assert!(output.is_empty());
        }

        #[test]
        fn interactive_pause_requires_a_terminal_and_enter() {
            let mut input = std::io::Cursor::new(Vec::<u8>::new());
            let mut output = Vec::new();
            assert!(
                wait_for_inspection(false, false, &mut input, &mut output)
                    .unwrap_err()
                    .to_string()
                    .contains("--noninteractive")
            );

            let mut input = std::io::Cursor::new(b"\n".to_vec());
            wait_for_inspection(false, true, &mut input, &mut output).unwrap();
            assert!(String::from_utf8(output).unwrap().contains("Press Enter"));
        }

        #[test]
        fn controls_have_plain_english_explanations() {
            let memory = control_explanation(&ProcessControl::MemoryLimit(512 << 20));
            assert!(memory.contains("512 MiB"));
            let child = control_explanation(&ProcessControl::DenyChildProcesses);
            assert!(child.contains("process"));
            assert!(!child.contains("ProcessControl"));
        }

        #[test]
        fn output_directory_must_be_new_below_an_existing_parent() {
            let parent = tempfile::tempdir().unwrap();
            let output = parent.path().join("run");
            create_output(&output).unwrap();
            assert!(
                create_output(&output)
                    .unwrap_err()
                    .to_string()
                    .contains("already exists")
            );
            assert!(
                create_output(&parent.path().join("missing").join("run"))
                    .unwrap_err()
                    .to_string()
                    .contains("Create only its parent")
            );
        }

        #[cfg(target_os = "windows")]
        #[test]
        fn windows_output_path_budget_accepts_boundary_and_rejects_next_unit() {
            let parent = tempfile::tempdir().unwrap();
            let canonical_parent = std::fs::canonicalize(parent.path()).unwrap();
            let parent_units = windows_legacy_path_units(&canonical_parent);
            let suffix_units = windows_legacy_path_units(
                &Path::new("snapshot")
                    .join("blobs")
                    .join("sha256")
                    .join("0".repeat(64)),
            ) + 1;
            let maximum_root = 259 - suffix_units;
            let separator = usize::from(!canonical_parent.as_os_str().is_empty());
            let boundary_name = "x".repeat(maximum_root - parent_units - separator);
            let boundary = parent.path().join(&boundary_name);
            validate_output_path(&boundary).unwrap();
            let over = parent.path().join(format!("{boundary_name}x"));
            let error = validate_output_path(&over).unwrap_err().to_string();
            assert!(error.contains("the maximum is"));
            assert!(error.contains("Choose a shorter parent or output name"));
            assert!(!boundary.exists());
            assert!(!over.exists());
        }
    }
}

fn main() -> hyperlight_host::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    {
        // SAFETY: capture is the first operation, before threads or environment access.
        let startup = unsafe { hyperlight_host::process::ProcessStartup::capture() }?;
        match startup {
            Some(startup) => demo::run_process(startup),
            None => {
                env_logger::init();
                demo::run_controller()
            }
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    Err(hyperlight_host::new_error!(
        "This example requires Linux or Windows"
    ))
}
