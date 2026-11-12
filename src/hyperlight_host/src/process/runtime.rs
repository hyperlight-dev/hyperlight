// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures::FutureExt;
use mesh::rpc::RpcSend;
use mesh_process::Mesh;

use super::launch::{OwnedHost, PreparedProcess, ProcessGuard, ProcessLauncher, ProcessReport};
use super::program::{
    FunctionContractDefinition, ProcessDefinition, ProcessTopologyDefinition, ProgramRole,
};
use super::{Idempotency, transport};
use crate::{HostFunctions, HyperlightError, Result, new_error};

const CONTROL_TIMEOUT: Duration = Duration::from_secs(30);

/// Per-worker sliding-window restart budget and bounded exponential delay.
#[derive(Clone, Debug)]
pub struct RestartPolicy {
    /// Replacement attempts allowed within `window`. Zero disables replacement.
    pub max_restarts: usize,
    /// Period over which replacement attempts are counted.
    pub window: Duration,
    /// Delay before the first replacement attempt.
    pub initial_backoff: Duration,
    /// Upper bound for the exponentially increasing delay.
    pub max_backoff: Duration,
}

impl Default for RestartPolicy {
    fn default() -> Self {
        Self {
            max_restarts: 3,
            window: Duration::from_secs(60),
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(5),
        }
    }
}

impl RestartPolicy {
    fn validate(&self) -> Result<()> {
        if self.window.is_zero()
            || self.initial_backoff.is_zero()
            || self.max_backoff.is_zero()
            || self.initial_backoff > self.max_backoff
        {
            return Err(new_error!("Invalid function-process restart policy"));
        }
        Ok(())
    }

    fn reserve(&self, attempts: &mut VecDeque<Instant>, now: Instant) -> Result<Duration> {
        while attempts
            .front()
            .is_some_and(|at| now.duration_since(*at) >= self.window)
        {
            attempts.pop_front();
        }
        if attempts.len() >= self.max_restarts {
            return Err(new_error!("Function-process restart budget exhausted"));
        }
        let shift = u32::try_from(attempts.len()).unwrap_or(u32::MAX);
        let delay = self
            .initial_backoff
            .checked_mul(1_u32.checked_shl(shift).unwrap_or(u32::MAX))
            .unwrap_or(self.max_backoff)
            .min(self.max_backoff);
        attempts.push_back(now);
        Ok(delay)
    }
}

pub(crate) struct Runtime {
    mesh: Option<Mesh>,
    hosts: Mutex<Vec<Worker>>,
    launcher: Option<Arc<dyn ProcessLauncher>>,
    policy: RestartPolicy,
    poisoned: AtomicBool,
    poison_cause: Mutex<Option<String>>,
    stopped: AtomicBool,
    cancellation: Mutex<mesh::CancelContext>,
    cancel: Mutex<mesh::Cancel>,
}

struct Worker {
    definition: Option<ProcessDefinition>,
    instance: Option<Instance>,
    pending_launch: Option<HyperlightError>,
    attempts: VecDeque<Instant>,
    generation: u64,
    resource_generation: u64,
}

struct Instance {
    root: OwnedHost,
    requests: mesh::Sender<transport::Request>,
    guard: Arc<dyn ProcessGuard>,
    report: Option<ProcessReport>,
    export_handler: Option<super::resource::ExportHandler>,
}

impl Runtime {
    pub(crate) fn cleanup_startup_error(
        self: Arc<Self>,
        error: HyperlightError,
    ) -> HyperlightError {
        if let Err(cleanup) = self.stop() {
            tracing::error!(%cleanup, "Sandbox startup cleanup is incomplete");
            super::launch::ProcessCleanupError::retain(
                error,
                super::launch::CleanupOwner::Runtime { _owner: self },
            )
        } else {
            error
        }
    }

    #[cfg(test)]
    pub(super) fn new() -> Result<Arc<Self>> {
        Self::with_launcher(None, RestartPolicy::default())
    }

    /// VM-side health and cancellation, without a process-launch capability.
    pub(super) fn remote() -> Arc<Self> {
        let (cancellation, cancel) = mesh::CancelContext::new().with_cancel();
        Arc::new(Self {
            mesh: None,
            hosts: Mutex::new(Vec::new()),
            launcher: None,
            policy: RestartPolicy::default(),
            poisoned: AtomicBool::new(false),
            poison_cause: Mutex::new(None),
            stopped: AtomicBool::new(false),
            cancellation: Mutex::new(cancellation),
            cancel: Mutex::new(cancel),
        })
    }

    fn with_launcher(
        launcher: Option<Arc<dyn ProcessLauncher>>,
        policy: RestartPolicy,
    ) -> Result<Arc<Self>> {
        policy.validate()?;
        let (cancellation, cancel) = mesh::CancelContext::new().with_cancel();
        Ok(Arc::new(Self {
            #[cfg(not(target_os = "macos"))]
            mesh: Some(Mesh::new("hyperlight-sandbox".to_owned())?),
            #[cfg(target_os = "macos")]
            mesh: None,
            hosts: Mutex::new(Vec::new()),
            launcher,
            policy,
            poisoned: AtomicBool::new(false),
            poison_cause: Mutex::new(None),
            stopped: AtomicBool::new(false),
            cancellation: Mutex::new(cancellation),
            cancel: Mutex::new(cancel),
        }))
    }

    pub(crate) fn is_poisoned(&self) -> bool {
        self.poisoned.load(Ordering::Acquire)
    }

    pub(super) fn mark_poisoned(&self) {
        self.poisoned.store(true, Ordering::Release);
    }

    pub(super) fn mark_poisoned_with_cause(&self, cause: String) {
        self.store_poison_cause(cause);
        self.mark_poisoned();
    }

    #[cfg(test)]
    pub(crate) fn poison_cause(&self) -> Option<String> {
        self.poison_cause
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }

    fn record_poison_cause(&self, error: &HyperlightError) {
        let mut chain = error.to_string();
        let mut source = std::error::Error::source(error);
        while let Some(error) = source {
            chain.push_str(": ");
            chain.push_str(&error.to_string());
            source = error.source();
        }
        tracing::error!(error = %chain, error_debug = ?error, "Function-process lifecycle recovery failed");
        self.store_poison_cause(chain);
    }

    fn store_poison_cause(&self, chain: String) {
        let mut cause = self
            .poison_cause
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if cause.is_none() {
            *cause = Some(chain);
        }
    }

    pub(super) fn ensure_active(&self) -> Result<()> {
        if self.stopped.load(Ordering::Acquire) || self.is_poisoned() {
            return Err(new_error!(
                "Owning sandbox process runtime is stopped or poisoned"
            ));
        }
        Ok(())
    }

    pub(super) fn worker_generation(&self, index: usize) -> Result<transport::WorkerGeneration> {
        self.ensure_active()?;
        let hosts = self
            .hosts
            .lock()
            .map_err(|error| new_error!("Worker ownership lock failed: {error}"))?;
        self.ensure_active()?;
        Self::generation(
            hosts
                .get(index)
                .ok_or_else(|| new_error!("Unknown function-process owner"))?,
        )
    }

    fn generation(worker: &Worker) -> Result<transport::WorkerGeneration> {
        let definition = worker
            .definition
            .as_ref()
            .ok_or_else(|| new_error!("Worker has no recovery definition"))?;
        let instance = worker
            .instance
            .as_ref()
            .ok_or_else(|| new_error!("Function-process is unavailable"))?;
        Ok(transport::WorkerGeneration::new(
            worker.generation,
            instance.requests.clone(),
            definition.functions(),
        ))
    }

    /// The lifecycle protocol never transports function-call payloads or results.
    pub(super) fn refresh_worker(
        &self,
        index: usize,
        observed_generation: u64,
    ) -> Result<transport::WorkerGeneration> {
        let mut hosts = self
            .hosts
            .lock()
            .map_err(|error| new_error!("Worker ownership lock failed: {error}"))?;
        self.ensure_active()?;
        let worker = hosts
            .get_mut(index)
            .ok_or_else(|| new_error!("Unknown function-process owner"))?;
        if observed_generation > worker.generation {
            return Err(new_error!("Unknown future function-process generation"));
        }
        if observed_generation == worker.generation
            && let Err(error) = self.recover(worker)
        {
            if self.is_poisoned() {
                self.record_poison_cause(&error);
            }
            return Err(error);
        }
        Self::generation(worker)
    }

    pub(super) fn cancellation(&self) -> mesh::CancelContext {
        self.cancellation
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }

    pub(crate) fn reports(&self) -> Vec<ProcessReport> {
        self.hosts
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .iter()
            .filter_map(|worker| worker.instance.as_ref()?.report.clone())
            .collect()
    }

    #[cfg(all(test, target_os = "windows"))]
    pub(crate) fn terminate_worker_for_test(&self, index: usize) -> Result<()> {
        let hosts = self.hosts.lock().unwrap();
        hosts[index]
            .instance
            .as_ref()
            .unwrap()
            .root
            .terminate_root()?;
        Ok(())
    }

    /// All physical endpoints in a sandbox originate on the same parent node.
    pub(super) async fn launch_sandbox(
        &self,
        config: mesh_process::ProcessConfig,
        bootstrap: super::sandbox::Bootstrap,
        guard: Arc<dyn ProcessGuard>,
    ) -> Result<OwnedHost> {
        #[cfg(not(target_os = "macos"))]
        return super::launch::launch_owned(
            self.mesh
                .as_ref()
                .ok_or_else(|| new_error!("Process runtime stopped"))?,
            config,
            bootstrap,
            guard,
            self.cancellation(),
            CONTROL_TIMEOUT,
        )
        .await;
        #[cfg(target_os = "macos")]
        return super::launch::launch_legacy_owned(
            config,
            bootstrap,
            guard,
            self.cancellation(),
            CONTROL_TIMEOUT,
        )
        .await;
    }

    /// The factory must validate every program before this method is called.
    /// All configurations are prepared before the first process is launched.
    pub(super) fn start_workers(
        definitions: &[ProcessDefinition],
        launcher: Arc<dyn ProcessLauncher>,
        policy: RestartPolicy,
    ) -> Result<Arc<Self>> {
        policy.validate()?;
        let prepared = definitions
            .iter()
            .map(|definition| launcher.prepare(ProgramRole::FunctionWorker, definition))
            .collect::<Result<Vec<_>>>()?;
        let runtime = Self::with_launcher(Some(launcher), policy)?;
        for (definition, prepared) in definitions.iter().zip(prepared) {
            let mut hosts = runtime
                .hosts
                .lock()
                .map_err(|error| new_error!("Worker ownership lock failed: {error}"))?;
            hosts.push(Worker {
                definition: Some(definition.clone()),
                instance: None,
                pending_launch: None,
                attempts: VecDeque::new(),
                generation: 0,
                resource_generation: 0,
            });
            let result = futures_lite::future::block_on(
                runtime.spawn_ready(hosts.last_mut().unwrap(), prepared),
            );
            drop(hosts);
            if let Err(error) = result {
                let cleanup = runtime.stop();
                if let Err(cleanup) = cleanup {
                    tracing::error!(%cleanup, "Worker startup cleanup is incomplete");
                    return Err(super::launch::ProcessCleanupError::retain(
                        error,
                        super::launch::CleanupOwner::Runtime { _owner: runtime },
                    ));
                }
                return Err(error);
            }
        }
        Ok(runtime)
    }

    #[allow(deprecated)]
    async fn spawn_ready(&self, worker: &mut Worker, mut prepared: PreparedProcess) -> Result<()> {
        self.ensure_active()?;
        if worker.instance.is_some() || worker.pending_launch.is_some() {
            return Err(new_error!(
                "Function-process owner still retains an instance"
            ));
        }
        let definition = worker
            .definition
            .as_ref()
            .ok_or_else(|| new_error!("Worker has no recovery definition"))?;
        let (requests, receive) = mesh::channel();
        let (ready, readiness) = mesh::oneshot();
        let resource_generation = match prepared.resource_generation.as_ref() {
            Some(generation) => generation
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |generation| {
                    generation.checked_add(1)
                })
                .map_err(|_| new_error!("Process resource generation exhausted"))?,
            None => worker
                .resource_generation
                .checked_add(1)
                .ok_or_else(|| new_error!("Process resource generation exhausted"))?,
        };
        let resource_declarations = prepared
            .resources
            .iter()
            .map(|resource| resource.declaration(resource_generation))
            .collect();
        let export_policy = prepared
            .export_authority
            .as_ref()
            .map(super::resource::ExportAuthority::declaration);
        worker.resource_generation = resource_generation;
        prepared.config = prepared.config.env([(
            std::ffi::OsString::from("HYPERLIGHT_VM_AUTHORITY_GENERATION"),
            resource_generation.to_string().into(),
        )]);
        let bootstrap = transport::bootstrap_with_resources(
            definition.functions(),
            resource_generation,
            resource_declarations,
            export_policy,
            receive,
            ready,
        );
        let controls = prepared.controls.clone();
        let windows_policy = prepared.windows_policy.clone();
        // Readiness failure must leave cleanup ownership in the same worker slot.
        worker.instance = Some(
            match self
                .spawn(prepared, bootstrap, requests, resource_generation)
                .await
            {
                Ok(instance) => instance,
                Err(error) if super::launch::has_cleanup_owner(&error) => {
                    let message = error.to_string();
                    // RPC diagnostics must not consume retained native cleanup ownership.
                    worker.pending_launch = Some(error);
                    self.poisoned.store(true, Ordering::Release);
                    return Err(new_error!("{message}"));
                }
                Err(error) => return Err(error),
            },
        );
        let instance = worker.instance.as_mut().unwrap();
        let readiness = self
            .cancellation()
            .until_cancelled(transport::wait_ready(readiness))
            .await
            .map_err(|error| new_error!("Worker readiness cancelled: {error}"))
            .and_then(|result| result);
        if let Err(error) = readiness {
            let cleanup = cleanup(instance, false).await;
            if cleanup.is_err() {
                self.poisoned.store(true, Ordering::Release);
            } else {
                worker.instance = None;
            }
            return Err(new_error!(
                "Worker readiness failed: {error}; cleanup: {cleanup:?}"
            ));
        }
        instance.report = Some(ProcessReport {
            role: ProgramRole::FunctionWorker,
            name: definition.name().to_owned(),
            program: definition.program().clone(),
            root_process_id: instance.root.id(),
            controls,
            windows_policy,
        });
        Ok(())
    }

    async fn spawn(
        &self,
        prepared: PreparedProcess,
        bootstrap: transport::PreparedBootstrap,
        requests: mesh::Sender<transport::Request>,
        resource_generation: u64,
    ) -> Result<Instance> {
        let PreparedProcess {
            config,
            guard,
            resources,
            export_authority,
            ..
        } = prepared;
        let transport::PreparedBootstrap { wire, mut delivery } = bootstrap;
        #[cfg(not(target_os = "macos"))]
        let launch = super::launch::launch_owned(
            self.mesh
                .as_ref()
                .ok_or_else(|| new_error!("Process runtime stopped"))?,
            config,
            wire,
            guard.clone(),
            self.cancellation(),
            CONTROL_TIMEOUT,
        )
        .await;
        #[cfg(target_os = "macos")]
        let launch = super::launch::launch_legacy_owned(
            config,
            wire,
            guard.clone(),
            self.cancellation(),
            CONTROL_TIMEOUT,
        )
        .await;
        let mut root = match launch {
            Ok(root) => root,
            Err(error) => {
                if super::launch::has_cleanup_owner(&error) {
                    self.poisoned.store(true, Ordering::Release);
                }
                return Err(error);
            }
        };
        if let Err(error) = self
            .cancellation()
            .with_timeout(CONTROL_TIMEOUT)
            .until_cancelled(delivery.wait_validated())
            .await
            .map_err(|error| new_error!("Function-process validation timed out: {error}"))
            .and_then(|result| result)
        {
            let cleanup = super::launch::cleanup_owned(
                &mut root,
                guard.as_ref(),
                Instant::now() + CONTROL_TIMEOUT,
            )
            .await;
            let error =
                new_error!("Function-process validation failed: {error}; cleanup: {cleanup:?}");
            return match cleanup {
                Ok(()) => Err(error),
                Err(_) => Err(super::launch::retain_confirmed_cleanup(
                    error,
                    root,
                    guard,
                    Instant::now() + CONTROL_TIMEOUT,
                )),
            };
        }
        let resource_setup: Result<_> = (|| {
            let resources = resources
                .into_iter()
                .map(|resource| resource.instantiate(resource_generation))
                .collect::<Result<Vec<_>>>()?;
            let (exports, export_handler) = match export_authority {
                Some(authority) => {
                    let (exports, thread) = authority.start(resource_generation)?;
                    (Some(exports), Some(thread))
                }
                None => (None, None),
            };
            Ok((resources, exports, export_handler))
        })();
        let (resources, exports, export_handler) = match resource_setup {
            Ok(setup) => setup,
            Err(error) => {
                let cleanup = super::launch::cleanup_owned(
                    &mut root,
                    guard.as_ref(),
                    Instant::now() + CONTROL_TIMEOUT,
                )
                .await;
                let error = new_error!(
                    "Function-process resource setup failed: {error}; cleanup: {cleanup:?}"
                );
                return match cleanup {
                    Ok(()) => Err(error),
                    Err(_) => Err(super::launch::retain_confirmed_cleanup(
                        error,
                        root,
                        guard,
                        Instant::now() + CONTROL_TIMEOUT,
                    )),
                };
            }
        };
        delivery.send_resources(resource_generation, resources, exports);
        Ok(Instance {
            root,
            requests,
            guard,
            report: None,
            export_handler,
        })
    }

    #[cfg(test)]
    #[allow(deprecated)]
    async fn launch_guarded(
        &self,
        prepared: PreparedProcess,
        bootstrap: transport::PreparedBootstrap,
        requests: mesh::Sender<transport::Request>,
    ) -> Result<i32> {
        let resource_generation = match prepared.resource_generation.as_ref() {
            Some(generation) => generation
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |generation| {
                    generation.checked_add(1)
                })
                .map_err(|_| new_error!("Process resource generation exhausted"))?,
            None => 1,
        };
        let instance = self
            .spawn(prepared, bootstrap, requests, resource_generation)
            .await?;
        let id = instance.root.id();
        self.hosts
            .lock()
            .map_err(|error| new_error!("Worker ownership lock failed: {error}"))?
            .push(Worker {
                definition: None,
                instance: Some(instance),
                pending_launch: None,
                attempts: VecDeque::new(),
                generation: 0,
                resource_generation: 0,
            });
        Ok(id)
    }

    #[cfg(test)]
    pub(super) fn terminate_fixture_root(&self, index: usize) {
        let mut hosts = self.hosts.lock().unwrap();
        let instance = hosts[index].instance.as_mut().unwrap();
        instance.root.terminate_root().unwrap();
        futures_lite::future::block_on(instance.root.wait_root()).unwrap();
    }

    #[cfg(test)]
    pub(super) async fn launch(
        &self,
        config: mesh_process::ProcessConfig,
        bootstrap: transport::PreparedBootstrap,
        requests: mesh::Sender<transport::Request>,
    ) -> Result<i32> {
        self.launch_with_resources(config, bootstrap, requests, vec![], None)
            .await
    }

    #[cfg(test)]
    pub(super) async fn launch_with_resources(
        &self,
        config: mesh_process::ProcessConfig,
        bootstrap: transport::PreparedBootstrap,
        requests: mesh::Sender<transport::Request>,
        resources: Vec<super::resource::RegisteredResource>,
        export_authority: Option<super::resource::ExportAuthority>,
    ) -> Result<i32> {
        self.launch_with_resources_generation(
            config,
            bootstrap,
            requests,
            resources,
            export_authority,
            None,
        )
        .await
    }

    #[cfg(test)]
    pub(super) async fn launch_with_resources_generation(
        &self,
        config: mesh_process::ProcessConfig,
        bootstrap: transport::PreparedBootstrap,
        requests: mesh::Sender<transport::Request>,
        resources: Vec<super::resource::RegisteredResource>,
        export_authority: Option<super::resource::ExportAuthority>,
        resource_generation: Option<Arc<std::sync::atomic::AtomicU64>>,
    ) -> Result<i32> {
        self.launch_guarded(
            PreparedProcess {
                config,
                guard: Arc::new(TrustedFixtureGuard),
                controls: vec![],
                windows_policy: None,
                resources,
                export_authority,
                resource_generation,
            },
            bootstrap,
            requests,
        )
        .await
    }

    /// Serialization is intentional. Native host calls have a synchronous local ABI.
    pub(super) fn invoke(
        &self,
        worker_index: usize,
        definition: &FunctionContractDefinition,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>> {
        self.ensure_active()?;
        let mut hosts = self
            .hosts
            .lock()
            .map_err(|error| new_error!("Worker ownership lock failed: {error}"))?;
        self.ensure_active()?;
        let worker = hosts
            .get_mut(worker_index)
            .ok_or_else(|| new_error!("Unknown function-process owner"))?;
        let owner = worker
            .definition
            .as_ref()
            .ok_or_else(|| new_error!("Worker has no recovery definition"))?;
        if !owner.functions().contains(definition) {
            return Err(new_error!(
                "Function-process contract differs from immutable registration"
            ));
        }
        loop {
            self.ensure_active()?;
            let exited = worker
                .instance
                .as_mut()
                .ok_or_else(|| new_error!("Function-process is unavailable"))?
                .root
                .wait_root()
                .now_or_never()
                .is_some();
            if exited {
                // No request has been enqueued in this iteration. Replacing an
                // already exited root therefore needs no replay permission.
                self.recover(worker)?;
                continue;
            }
            let instance = worker
                .instance
                .as_ref()
                .ok_or_else(|| new_error!("Function-process is unavailable"))?;
            let response = futures_lite::future::block_on(
                self.cancellation().until_cancelled(
                    instance
                        .requests
                        .call(transport::Request::Call, payload.clone()),
                ),
            )
            .map_err(|error| new_error!("Intentional function-process stop: {error}"))?;
            match response {
                Ok(response) => {
                    return response
                        .map_err(|error| new_error!("Host-function process call failed: {error}"));
                }
                Err(error) => {
                    // Enqueuing an RPC is not an execution acknowledgment. A missing
                    // response can never establish that user code did not execute.
                    self.recover(worker)?;
                    if definition.idempotency() != Idempotency::Idempotent {
                        return Err(new_error!(
                            "Host-function process disconnected; execution is uncertain and replay is forbidden: {error}"
                        ));
                    }
                }
            }
        }
    }

    fn recover(&self, worker: &mut Worker) -> Result<()> {
        if self.stopped.load(Ordering::Acquire) {
            return Err(new_error!("Intentional function-process stop"));
        }
        if worker.generation == u64::MAX {
            self.mark_poisoned();
            return Err(new_error!("Function-process generation exhausted"));
        }
        if let Some(mut instance) = worker.instance.take()
            && let Err(error) = futures_lite::future::block_on(cleanup(&mut instance, false))
        {
            // Keep the domain capability for a final cleanup attempt on teardown.
            worker.instance = Some(instance);
            self.poisoned.store(true, Ordering::Release);
            return Err(new_error!(
                "Function-process cleanup failed; owning sandbox poisoned: {error}"
            ));
        }
        loop {
            if self.stopped.load(Ordering::Acquire) {
                return Err(new_error!("Intentional function-process stop"));
            }
            let delay = match self.policy.reserve(&mut worker.attempts, Instant::now()) {
                Ok(delay) => delay,
                Err(error) => {
                    self.poisoned.store(true, Ordering::Release);
                    return Err(error);
                }
            };
            // This bridge never relies on progress from a caller's async executor.
            let _ = futures_lite::future::block_on(
                self.cancellation()
                    .with_timeout(delay)
                    .until_cancelled(std::future::pending::<()>()),
            );
            if self.stopped.load(Ordering::Acquire) {
                return Err(new_error!("Intentional function-process stop"));
            }
            let attempt = self
                .launcher
                .as_ref()
                .ok_or_else(|| new_error!("Worker has no recovery launcher"))
                .and_then(|launcher| {
                    launcher.prepare(
                        ProgramRole::FunctionWorker,
                        worker.definition.as_ref().unwrap(),
                    )
                })
                .and_then(|prepared| {
                    futures_lite::future::block_on(self.spawn_ready(worker, prepared))
                });
            match attempt {
                Ok(()) => {
                    worker.generation += 1;
                    return Ok(());
                }
                Err(error) => {
                    if self.stopped.load(Ordering::Acquire) {
                        return Err(new_error!("Intentional function-process stop: {error}"));
                    }
                    if self.is_poisoned() {
                        return Err(new_error!(
                            "Function-process replacement cleanup failed; owning sandbox poisoned: {error}"
                        ));
                    }
                    tracing::warn!(%error, worker = worker.definition.as_ref().unwrap().name(), "Function-process replacement failed");
                }
            }
        }
    }

    /// Cancels in-flight calls before taking the ownership lock for bounded cleanup.
    pub(crate) fn stop(&self) -> Result<()> {
        self.stopped.store(true, Ordering::Release);
        self.cancel
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .cancel();
        let mut hosts = self.hosts.lock().unwrap_or_else(|error| error.into_inner());
        futures_lite::future::block_on(async {
            let results = futures::future::join_all(hosts.iter_mut().map(|worker| async {
                if let Some(instance) = worker.instance.as_mut() {
                    cleanup(instance, true).await?;
                    worker.instance = None;
                }
                if let Some(error) = &worker.pending_launch {
                    super::launch::retry_retained_cleanup(error, Instant::now() + CONTROL_TIMEOUT)?;
                    worker.pending_launch = None;
                }
                Ok(())
            }))
            .await;
            let errors: Vec<_> = results.into_iter().filter_map(Result::err).collect();
            if !errors.is_empty() {
                return Err(new_error!(
                    "Incomplete process cleanup: {}",
                    errors
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(". ")
                ));
            }
            Ok(())
        })
    }

    pub(super) fn shutdown(&mut self) -> Result<()> {
        self.stop()?;
        let Some(mesh) = self.mesh.take() else {
            return Ok(());
        };
        futures_lite::future::block_on(async {
            mesh::CancelContext::new()
                .with_timeout(CONTROL_TIMEOUT)
                .until_cancelled(mesh.shutdown())
                .await
                .map_err(|error| new_error!("Process mesh shutdown timed out: {error}"))?;
            Ok(())
        })
    }
}

async fn cleanup(instance: &mut Instance, graceful: bool) -> Result<()> {
    let deadline = Instant::now() + CONTROL_TIMEOUT;
    if let Some(handler) = instance.export_handler.as_mut() {
        handler.stop();
    }
    if graceful {
        drop(instance.requests.call(transport::Request::Stop, ()));
        let _ = mesh::CancelContext::new()
            .with_timeout(Duration::from_millis(250))
            .until_cancelled(instance.root.wait_root())
            .await;
    }
    super::launch::cleanup_owned(&mut instance.root, instance.guard.as_ref(), deadline).await?;
    if let Some(handler) = instance.export_handler.as_mut() {
        handler.join(deadline)?;
    }
    instance.export_handler = None;
    Ok(())
}

pub(super) fn start_with_policy(
    definition: ProcessTopologyDefinition,
    launcher: Arc<dyn ProcessLauncher>,
    local: &mut HostFunctions,
    policy: RestartPolicy,
) -> Result<()> {
    definition.validate()?;
    if definition.sandbox().is_some() {
        return Err(new_error!(
            "Dedicated sandbox topology requires the dedicated process launcher"
        ));
    }
    for worker in definition.workers() {
        for function in worker.functions() {
            if local.inner().function_signature(function.name()).is_some() {
                return Err(new_error!(
                    "Duplicate local/process owner for '{}'",
                    function.name()
                ));
            }
        }
    }
    let runtime = Runtime::start_workers(definition.workers(), launcher, policy)?;
    for (index, worker) in definition.workers().iter().enumerate() {
        for (name, entry) in
            transport::register_runtime_routes(index, worker.functions(), runtime.clone())
                .into_iter()
        {
            local.inner_mut().register_host_function(name, entry);
        }
    }
    local.inner_mut().process_topology = Some(Box::new(definition));
    local.inner_mut().process_runtime = Some(runtime);
    Ok(())
}

// Trusted main-entry fixtures qualify transport, not OS confinement.
#[cfg(test)]
pub(super) struct TrustedFixtureGuard;

#[cfg(test)]
impl ProcessGuard for TrustedFixtureGuard {
    fn start_launch(&self) {}
    fn terminate_domain(&self) -> Result<()> {
        Ok(())
    }
    fn wait_empty(&self, _deadline: Instant) -> Result<()> {
        Ok(())
    }

    fn release_resources(&self, _deadline: Instant) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
pub(super) fn start_prepared(
    definition: ProcessTopologyDefinition,
    launches: Vec<mesh_process::ProcessConfig>,
    local: &mut HostFunctions,
) -> Result<()> {
    struct OnceLauncher(Mutex<VecDeque<mesh_process::ProcessConfig>>);
    impl ProcessLauncher for OnceLauncher {
        fn prepare(
            &self,
            _role: ProgramRole,
            _definition: &ProcessDefinition,
        ) -> Result<PreparedProcess> {
            Ok(PreparedProcess {
                config: self.0.lock().unwrap().pop_front().ok_or_else(|| {
                    new_error!("Trusted fixture has no replacement configuration")
                })?,
                guard: Arc::new(TrustedFixtureGuard),
                controls: vec![],
                windows_policy: None,
                resources: vec![],
                export_authority: None,
                resource_generation: None,
            })
        }
    }
    if launches.len() != definition.workers().len() {
        return Err(new_error!("Prepared process count does not match topology"));
    }
    start_with_policy(
        definition,
        Arc::new(OnceLauncher(Mutex::new(launches.into()))),
        local,
        RestartPolicy::default(),
    )
}

impl Drop for Runtime {
    fn drop(&mut self) {
        if let Err(error) = self.shutdown() {
            tracing::error!(%error, "Final runtime cleanup failed. Dropping this cleanup owner");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_budget_is_sliding_and_backoff_is_exponential_and_capped() {
        let policy = RestartPolicy::default();
        let now = Instant::now();
        let mut attempts = VecDeque::new();
        assert_eq!(
            policy.reserve(&mut attempts, now).unwrap(),
            Duration::from_millis(100)
        );
        assert_eq!(
            policy.reserve(&mut attempts, now).unwrap(),
            Duration::from_millis(200)
        );
        assert_eq!(
            policy.reserve(&mut attempts, now).unwrap(),
            Duration::from_millis(400)
        );
        assert!(
            policy
                .reserve(&mut attempts, now + Duration::from_secs(59))
                .is_err()
        );
        assert_eq!(
            policy
                .reserve(&mut attempts, now + Duration::from_secs(60))
                .unwrap(),
            Duration::from_millis(100)
        );

        let policy = RestartPolicy {
            max_restarts: 10,
            max_backoff: Duration::from_millis(150),
            ..Default::default()
        };
        attempts.clear();
        assert_eq!(
            policy.reserve(&mut attempts, now).unwrap(),
            Duration::from_millis(100)
        );
        assert_eq!(
            policy.reserve(&mut attempts, now).unwrap(),
            Duration::from_millis(150)
        );
        assert_eq!(
            policy.reserve(&mut attempts, now).unwrap(),
            Duration::from_millis(150)
        );
    }

    #[test]
    fn recovery_policy_can_disable_restarts_and_rejects_invalid_delays() {
        let policy = RestartPolicy {
            max_restarts: 0,
            ..Default::default()
        };
        assert!(
            policy
                .reserve(&mut VecDeque::new(), Instant::now())
                .is_err()
        );
        assert!(
            RestartPolicy {
                window: Duration::ZERO,
                ..Default::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            RestartPolicy {
                initial_backoff: Duration::from_secs(6),
                ..Default::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            RestartPolicy {
                initial_backoff: Duration::ZERO,
                ..Default::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            RestartPolicy {
                max_backoff: Duration::ZERO,
                ..Default::default()
            }
            .validate()
            .is_err()
        );
    }
}
