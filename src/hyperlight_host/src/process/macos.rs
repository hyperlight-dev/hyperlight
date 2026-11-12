// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use super::launch::{PreparedProcess, ProcessGuard};
use super::program::{ProcessDefinition, ProgramRole, ValidatedProgram};
use crate::{Result, new_error};

struct UnrestrictedGuard {
    image: Mutex<Option<tempfile::TempDir>>,
}

impl ProcessGuard for UnrestrictedGuard {
    fn start_launch(&self) {}

    fn terminate_domain(&self) -> Result<()> {
        Ok(())
    }

    fn wait_empty(&self, _deadline: Instant) -> Result<()> {
        Ok(())
    }

    fn release_resources(&self, _deadline: Instant) -> Result<()> {
        self.image
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        Ok(())
    }
}

fn stage_program(program: &ValidatedProgram) -> Result<(tempfile::TempDir, std::path::PathBuf)> {
    let image = tempfile::Builder::new()
        .prefix("hyperlight-unrestricted-")
        .tempdir()?;
    let image_root = image.path().canonicalize()?;
    if std::fs::symlink_metadata(image.path())?
        .file_type()
        .is_symlink()
    {
        return Err(new_error!("macOS private process image is a symlink"));
    }
    let executable = image_root.join("program");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&executable)?;
    file.write_all(program.executable())?;
    file.set_permissions(std::fs::Permissions::from_mode(0o500))?;
    drop(file);
    let executable = executable.canonicalize()?;
    if !executable.starts_with(&image_root)
        || std::fs::symlink_metadata(&executable)?
            .file_type()
            .is_symlink()
    {
        return Err(new_error!(
            "macOS staged executable escaped its private image"
        ));
    }
    Ok((image, executable))
}

pub(super) fn prepare(
    role: ProgramRole,
    definition: &ProcessDefinition,
    program: &ValidatedProgram,
) -> Result<PreparedProcess> {
    let profile = definition.profile();
    profile.validate()?;
    if !profile.is_unrestricted() {
        return Err(new_error!(
            "Restricted process profiles are not implemented on macOS"
        ));
    }
    if !program.runtime_files().is_empty() {
        return Err(new_error!(
            "macOS unrestricted process preparation requires a self-contained executable"
        ));
    }
    if program.config().role != role
        || program.config().target.os != "macos"
        || program.config().target.architecture != std::env::consts::ARCH
    {
        return Err(new_error!(
            "macOS program identity, role or target mismatch"
        ));
    }

    let (image, executable) = stage_program(program)?;

    let guard = Arc::new(UnrestrictedGuard {
        image: Mutex::new(Some(image)),
    });
    let config = mesh_process::ProcessConfig::new(definition.name())
        .process_name(executable)
        .skip_worker_arg(true);
    Ok(PreparedProcess {
        config,
        guard,
        controls: Vec::new(),
        windows_policy: None,
        resources: Vec::new(),
        export_authority: None,
        resource_generation: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::program::{
        FunctionContractDefinition, LocalProgramStore, ProgramConfig, ProgramFile, ProgramTarget,
    };
    use crate::process::{
        HostFunctionContract, Idempotency, ProcessControl, ProcessProfile, RequestedControl,
    };

    fn validated(role: ProgramRole) -> (tempfile::TempDir, ValidatedProgram, ProcessDefinition) {
        let directory = tempfile::tempdir().unwrap();
        let store = LocalProgramStore::new(directory.path().join("store"));
        let functions = (role == ProgramRole::FunctionWorker)
            .then(|| {
                vec![FunctionContractDefinition::from_contract(
                    &HostFunctionContract::<(), i32>::new("worker", Idempotency::Idempotent),
                )]
            })
            .unwrap_or_default();
        let config = ProgramConfig {
            schema_version: 1,
            role,
            target: ProgramTarget::current(Default::default()),
            functions: functions.clone(),
        };
        let artifact = store.package(&config, b"native program").unwrap();
        let definition = ProcessDefinition::new(
            "native",
            artifact.clone(),
            &ProcessProfile::unrestricted(),
            functions,
        )
        .unwrap();
        let program = store.validate(&artifact, &config.target).unwrap();
        (directory, program, definition)
    }

    #[test]
    fn stages_fixed_private_executable_and_cleans_up() {
        let (_directory, program, _definition) = validated(ProgramRole::SandboxHost);
        let (image, executable) = stage_program(&program).unwrap();
        let image_path = image.path().to_owned();

        assert!(executable.is_absolute());
        assert_eq!(
            executable.file_name(),
            Some(std::ffi::OsStr::new("program"))
        );
        assert_eq!(std::fs::read(&executable).unwrap(), b"native program");
        assert_eq!(
            std::fs::metadata(&executable).unwrap().permissions().mode() & 0o777,
            0o500
        );
        drop(image);
        assert!(!image_path.exists());
    }

    #[test]
    fn prepares_both_unrestricted_process_roles() {
        for role in [ProgramRole::SandboxHost, ProgramRole::FunctionWorker] {
            let (_directory, program, definition) = validated(role);
            let prepared = prepare(role, &definition, &program).unwrap();
            assert!(prepared.controls.is_empty());
        }
    }

    #[test]
    fn rejects_restricted_profiles_before_preparation() {
        let (_directory, program, mut definition) = validated(ProgramRole::SandboxHost);
        let artifact = definition.program().clone();
        definition = ProcessDefinition::new(
            "native",
            artifact,
            &ProcessProfile::new([RequestedControl {
                control: ProcessControl::DenyNetwork,
                required: true,
            }]),
            Vec::new(),
        )
        .unwrap();

        let error = prepare(ProgramRole::SandboxHost, &definition, &program)
            .err()
            .expect("Restricted macOS preparation must fail");

        assert!(error.to_string().contains("not implemented on macOS"));
    }

    #[test]
    fn rejects_runtime_file_closures_explicitly() {
        let directory = tempfile::tempdir().unwrap();
        let store = LocalProgramStore::new(directory.path().join("store"));
        let config = ProgramConfig {
            schema_version: 1,
            role: ProgramRole::SandboxHost,
            target: ProgramTarget::current(Default::default()),
            functions: Vec::new(),
        };
        let artifact = store
            .package_with_runtime(
                &config,
                b"native program",
                &[ProgramFile::new("/lib/helper.dylib", b"helper".to_vec()).unwrap()],
            )
            .unwrap();
        let definition = ProcessDefinition::new(
            "native",
            artifact.clone(),
            &ProcessProfile::unrestricted(),
            Vec::new(),
        )
        .unwrap();
        let program = store.validate(&artifact, &config.target).unwrap();

        let error = prepare(ProgramRole::SandboxHost, &definition, &program)
            .err()
            .expect("macOS preparation must reject runtime file closures");

        assert!(error.to_string().contains("self-contained executable"));
    }
}
