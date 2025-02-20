/*
Copyright 2024 The Hyperlight Authors.

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

#[cfg(target_os = "windows")]
use core::ffi::c_void;
use std::ops::DerefMut;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::thread::{sleep, JoinHandle};
use std::time::Duration;

#[cfg(target_os = "linux")]
use crossbeam::atomic::AtomicCell;
use crossbeam_channel::{Receiver, Sender};
#[cfg(target_os = "linux")]
use libc::{pthread_kill, pthread_self, ESRCH};
use log::{error, info};
use tracing::{instrument, Span};
#[cfg(target_os = "linux")]
use vmm_sys_util::signal::SIGRTMIN;
#[cfg(target_os = "windows")]
use windows::Win32::System::Hypervisor::{WHvCancelRunVirtualProcessor, WHV_PARTITION_HANDLE};

#[cfg(gdb)]
use super::gdb::create_gdb_thread;
#[cfg(feature = "function_call_metrics")]
use crate::histogram_vec_observe;
#[cfg(gdb)]
use crate::hypervisor::handlers::DbgMemAccessHandlerWrapper;
use crate::hypervisor::handlers::{MemAccessHandlerWrapper, OutBHandlerWrapper};
#[cfg(target_os = "windows")]
use crate::hypervisor::wrappers::HandleWrapper;
use crate::hypervisor::Hypervisor;
use crate::mem::layout::SandboxMemoryLayout;
use crate::mem::mgr::SandboxMemoryManager;
use crate::mem::ptr::{GuestPtr, RawPtr};
use crate::mem::ptr_offset::Offset;
use crate::mem::shared_mem::{GuestSharedMemory, HostSharedMemory, SharedMemory};
#[cfg(gdb)]
use crate::sandbox::config::DebugInfo;
use crate::sandbox::hypervisor::{get_available_hypervisor, HypervisorType};
#[cfg(feature = "function_call_metrics")]
use crate::sandbox::metrics::SandboxMetric::GuestFunctionCallDurationMicroseconds;
#[cfg(target_os = "linux")]
use crate::signal_handlers::setup_signal_handlers;
use crate::HyperlightError::{
    GuestExecutionHungOnHostFunctionCall,
    HypervisorHandlerExecutionCancelAttemptOnFinishedExecution, NoHypervisorFound,
};
use crate::{log_then_return, new_error, HyperlightError, Result};

type HypervisorHandlerTx = Sender<HypervisorHandlerAction>;
type HypervisorHandlerRx = Receiver<HypervisorHandlerAction>;
type HandlerMsgTx = Sender<HandlerMsg>;
type HandlerMsgRx = Receiver<HandlerMsg>;

#[derive(Clone)]
pub(crate) struct HypervisorHandler {
    communication_channels: HvHandlerCommChannels,
    configuration: HvHandlerConfig,
    execution_variables: HvHandlerExecVars,
}

impl HypervisorHandler {
    pub(crate) fn set_running(&self, running: bool) {
        self.execution_variables
            .running
            .store(running, Ordering::SeqCst);
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn set_run_cancelled(&self, run_cancelled: bool) {
        self.execution_variables.run_cancelled.store(run_cancelled);
    }
}

// Note: `join_handle` and `running` have to be `Arc` because we need
// this struct to be `Clone` to be able to pass it to the Hypervisor handler thread.
//
// `join_handle` also has to be `Mutex` because we need to be able to `take` it when we
// `try_join_hypervisor_handler_thread`.
#[derive(Clone)]
struct HvHandlerExecVars {
    join_handle: Arc<Mutex<Option<JoinHandle<Result<()>>>>>,
    shm: Arc<Mutex<Option<SandboxMemoryManager<GuestSharedMemory>>>>,
    timeout: Arc<Mutex<Duration>>,
    #[cfg(target_os = "linux")]
    thread_id: Arc<Mutex<Option<libc::pthread_t>>>,
    #[cfg(target_os = "windows")]
    partition_handle: Arc<Mutex<Option<WHV_PARTITION_HANDLE>>>,
    running: Arc<AtomicBool>,
    #[cfg(target_os = "linux")]
    run_cancelled: Arc<crossbeam::atomic::AtomicCell<bool>>,
}

impl HvHandlerExecVars {
    /// Sets the `join_handle`, to be called `thread::spawn` in `start_hypervisor_handler`.
    fn set_join_handle(&mut self, join_handle: JoinHandle<Result<()>>) -> Result<()> {
        *self
            .join_handle
            .try_lock()
            .map_err(|_| new_error!("Failed to set_join_handle"))? = Some(join_handle);

        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn set_thread_id(&mut self, thread_id: libc::pthread_t) -> Result<()> {
        *self
            .thread_id
            .try_lock()
            .map_err(|_| new_error!("Failed to set_thread_id"))? = Some(thread_id);

        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn get_thread_id(&self) -> Result<libc::pthread_t> {
        (*self
            .thread_id
            .try_lock()
            .map_err(|_| new_error!("Failed to get_thread_id"))?)
        .ok_or_else(|| new_error!("thread_id not set"))
    }

    #[cfg(target_os = "windows")]
    fn set_partition_handle(&mut self, partition_handle: WHV_PARTITION_HANDLE) -> Result<()> {
        *self
            .partition_handle
            .try_lock()
            .map_err(|_| new_error!("Failed to set_partition_handle"))? = Some(partition_handle);

        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn get_partition_handle(&self) -> Result<Option<WHV_PARTITION_HANDLE>> {
        Ok(*self
            .partition_handle
            .try_lock()
            .map_err(|_| new_error!("Failed to get_partition_handle"))?)
    }

    fn set_timeout(&mut self, timeout: Duration) -> Result<()> {
        *self
            .timeout
            .try_lock()
            .map_err(|_| new_error!("Failed to set_timeout"))? = timeout;

        Ok(())
    }

    fn get_timeout(&self) -> Result<Duration> {
        Ok(*self
            .timeout
            .try_lock()
            .map_err(|_| new_error!("Failed to get_timeout"))?)
    }
}

#[derive(Clone)]
struct HvHandlerCommChannels {
    to_handler_tx: HypervisorHandlerTx,
    to_handler_rx: HypervisorHandlerRx,
    from_handler_tx: HandlerMsgTx,
    from_handler_rx: HandlerMsgRx,
}

#[derive(Clone)]
pub(crate) struct HvHandlerConfig {
    pub(crate) peb_addr: RawPtr,
    pub(crate) seed: u64,
    pub(crate) page_size: u32,
    pub(crate) dispatch_function_addr: Arc<Mutex<Option<RawPtr>>>,
    pub(crate) max_init_time: Duration,
    pub(crate) max_exec_time: Duration,
    pub(crate) outb_handler: OutBHandlerWrapper,
    pub(crate) mem_access_handler: MemAccessHandlerWrapper,
    pub(crate) max_wait_for_cancellation: Duration,
    #[cfg(gdb)]
    pub(crate) dbg_mem_access_handler: DbgMemAccessHandlerWrapper,
}

impl HypervisorHandler {
    /// Creates a new Hypervisor Handler with a given configuration. This call must precede a call
    /// to `start_hypervisor_handler`.
    pub(crate) fn new(configuration: HvHandlerConfig) -> Self {
        let (to_handler_tx, to_handler_rx) = crossbeam_channel::unbounded();
        let (from_handler_tx, from_handler_rx) = crossbeam_channel::unbounded();

        let communication_channels = HvHandlerCommChannels {
            to_handler_tx,
            to_handler_rx,
            from_handler_tx,
            from_handler_rx,
        };

        let execution_variables = HvHandlerExecVars {
            join_handle: Arc::new(Mutex::new(None)),
            shm: Arc::new(Mutex::new(None)),
            #[cfg(target_os = "linux")]
            thread_id: Arc::new(Mutex::new(None)),
            #[cfg(target_os = "windows")]
            partition_handle: Arc::new(Mutex::new(None)),
            running: Arc::new(AtomicBool::new(false)),
            #[cfg(target_os = "linux")]
            run_cancelled: Arc::new(AtomicCell::new(false)),
            timeout: Arc::new(Mutex::new(configuration.max_init_time)),
        };

        Self {
            communication_channels,
            configuration,
            execution_variables,
        }
    }

    /// Sets up a Hypervisor 'handler', designed to listen to messages to execute a specific action,
    /// such as:
    /// - `initialise` resources,
    /// - `dispatch_call_from_host` in the vCPU, and
    /// - `terminate_execution` of the vCPU.
    ///
    /// To send messages to the hypervisor handler thread, use `execute_hypervisor_handler_action`.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    pub(crate) fn start_hypervisor_handler(
        &mut self,
        sandbox_memory_manager: SandboxMemoryManager<GuestSharedMemory>,
        #[cfg(gdb)] debug_info: Option<DebugInfo>,
    ) -> Result<()> {
        let configuration = self.configuration.clone();
        #[cfg(target_os = "windows")]
        let in_process = sandbox_memory_manager.is_in_process();

        *self.execution_variables.shm.try_lock().unwrap() = Some(sandbox_memory_manager);

        // Other than running initialization and code execution, the handler thread also handles
        // cancellation. When we need to cancel the execution there are 2 possible cases
        // we have to deal with depending on if the vCPU is currently running or not.
        //
        // 1. If the vCPU is executing, then we need to cancel the execution.
        // 2. If the vCPU is not executing, then we need to signal to the thread
        // that it should exit the loop.
        //
        // For the first case, on Linux, we send a signal to the thread running the
        // vCPU to interrupt it and cause an EINTR error on the underlying VM run call.
        //
        // For the second case, we set a flag that is checked on each iteration of the run loop
        // and if it is set to true then the loop will exit.

        // On Linux, we have another problem to deal with. The way we terminate a running vCPU
        // (case 1 above) is to send a signal to the thread running the vCPU to interrupt it.
        //
        // There is a possibility that the signal is sent and received just before the thread
        // calls run on the vCPU (between the check on the cancelled_run variable and the call to run)
        // - see this StackOverflow question for more details
        // https://stackoverflow.com/questions/25799667/fixing-race-condition-when-sending-signal-to-interrupt-system-call)
        //
        // To solve this, we need to keep sending the signal until we know that the spawned thread
        // knows it should cancel the execution.
        #[cfg(target_os = "linux")]
        self.execution_variables.run_cancelled.store(false);

        let to_handler_rx = self.communication_channels.to_handler_rx.clone();
        let mut execution_variables = self.execution_variables.clone();
        let from_handler_tx = self.communication_channels.from_handler_tx.clone();
        let hv_handler_clone = self.clone();

        // Hyperlight has two signal handlers:
        // (1) for timeouts, and
        // (2) for seccomp (when enabled).
        //
        // This sets up Hyperlight signal handlers for the process, which are chained
        // to the existing signal handlers.
        #[cfg(target_os = "linux")]
        setup_signal_handlers()?;

        let join_handle = {
            thread::Builder::new()
                .name("Hypervisor Handler".to_string())
                .spawn(move || -> Result<()> {
                    let mut hv: Option<Box<dyn Hypervisor>> = None;
                    for action in to_handler_rx {
                        match action {
                            HypervisorHandlerAction::Initialise => {
                                {
                                    hv = Some(set_up_hypervisor_partition(
                                        execution_variables.shm.try_lock().unwrap().deref_mut().as_mut().unwrap(),
                                        configuration.outb_handler.clone(),
                                        #[cfg(gdb)]
                                        &debug_info,
                                    )?);
                                }
                                let hv = hv.as_mut().unwrap();

                                #[cfg(target_os = "windows")]
                                if !in_process {
                                    execution_variables
                                        .set_partition_handle(hv.get_partition_handle())?;
                                }

                                #[cfg(target_os = "linux")]
                                {
                                    // We cannot use the Killable trait, so we get the `pthread_t` via a libc
                                    // call.
                                    execution_variables.set_thread_id(unsafe { pthread_self() })?;
                                }
                                execution_variables.running.store(true, Ordering::SeqCst);

                                #[cfg(target_os = "linux")]
                                execution_variables.run_cancelled.store(false);

                                log::info!("Initialising Hypervisor Handler");

                                let mut evar_lock_guard =
                                    execution_variables.shm.try_lock().map_err(|e| {
                                        new_error!(
                                            "Error locking exec var shm lock: {}:{}: {}",
                                            file!(),
                                            line!(),
                                            e
                                        )
                                    })?;
                                // This apparently-useless lock is
                                // needed to ensure the host does not
                                // make unsynchronized accesses while
                                // the guest is executing.  See the
                                // documentation for
                                // GuestSharedMemory::lock.
                                let mem_lock_guard = evar_lock_guard
                                    .as_mut()
                                    .ok_or_else(|| {
                                        new_error!("guest shm lock: {}:{}:", file!(), line!())
                                    })?
                                    .shared_mem
                                    .lock
                                    .try_read();

                                let res = hv.initialise(
                                    configuration.peb_addr.clone(),
                                    configuration.seed,
                                    configuration.page_size,
                                    configuration.outb_handler.clone(),
                                    configuration.mem_access_handler.clone(),
                                    Some(hv_handler_clone.clone()),
                                    #[cfg(gdb)]
                                    configuration.dbg_mem_access_handler.clone(),
                                );
                                drop(mem_lock_guard);
                                drop(evar_lock_guard);

                                execution_variables.running.store(false, Ordering::SeqCst);

                                match res {
                                    Ok(_) => {
                                        log::info!("Initialised Hypervisor Handler");
                                        from_handler_tx
                                            .send(HandlerMsg::FinishedHypervisorHandlerAction)
                                            .map_err(|_| {
                                                HyperlightError::HypervisorHandlerCommunicationFailure()
                                            })?;
                                    }
                                    Err(e) => {
                                        log::info!(
                                            "Error initialising Hypervisor Handler: {:?}",
                                            e
                                        );
                                        from_handler_tx.send(HandlerMsg::Error(e)).map_err(|_| {
                                            HyperlightError::HypervisorHandlerCommunicationFailure()
                                        })?;
                                    }
                                }
                            }
                            HypervisorHandlerAction::DispatchCallFromHost(function_name) => {
                                let hv = hv.as_mut().unwrap();

                                // Lock to indicate an action is being performed in the hypervisor
                                execution_variables.running.store(true, Ordering::SeqCst);

                                #[cfg(target_os = "linux")]
                                execution_variables.run_cancelled.store(false);

                                info!("Dispatching call from host: {}", function_name);

                                let dispatch_function_addr = configuration
                                    .dispatch_function_addr
                                    .clone()
                                    .try_lock()
                                    .map_err(|e| {
                                        new_error!(
                                            "Error locking at {}:{}: {}",
                                            file!(),
                                            line!(),
                                            e
                                        )
                                    })?
                                    .clone()
                                    .ok_or_else(|| new_error!("Hypervisor not initialized"))?;

                                let mut evar_lock_guard =
                                    execution_variables.shm.try_lock().map_err(|e| {
                                        new_error!(
                                            "Error locking exec var shm lock: {}:{}: {}",
                                            file!(),
                                            line!(),
                                            e
                                        )
                                    })?;
                                // This apparently-useless lock is
                                // needed to ensure the host does not
                                // make unsynchronized accesses while
                                // the guest is executing.  See the
                                // documentation for
                                // GuestSharedMemory::lock.
                                let mem_lock_guard = evar_lock_guard
                                    .as_mut()
                                    .ok_or_else(|| {
                                        new_error!("guest shm lock {}:{}", file!(), line!())
                                    })?
                                    .shared_mem
                                    .lock
                                    .try_read();

                                let res = {
                                    #[cfg(feature = "function_call_metrics")]
                                    {
                                        let start = std::time::Instant::now();
                                        let result = hv.dispatch_call_from_host(
                                            dispatch_function_addr,
                                            configuration.outb_handler.clone(),
                                            configuration.mem_access_handler.clone(),
                                            Some(hv_handler_clone.clone()),
                                            #[cfg(gdb)]
                                            configuration.dbg_mem_access_handler.clone(),
                                        );
                                        histogram_vec_observe!(
                                            &GuestFunctionCallDurationMicroseconds,
                                            &[function_name.as_str()],
                                            start.elapsed().as_micros() as f64
                                        );
                                        result
                                    }

                                    #[cfg(not(feature = "function_call_metrics"))]
                                    hv.dispatch_call_from_host(
                                        dispatch_function_addr,
                                        configuration.outb_handler.clone(),
                                        configuration.mem_access_handler.clone(),
                                        Some(hv_handler_clone.clone()),
                                        #[cfg(gdb)]
                                        configuration.dbg_mem_access_handler.clone(),
                                    )
                                };
                                drop(mem_lock_guard);
                                drop(evar_lock_guard);

                                execution_variables.running.store(false, Ordering::SeqCst);

                                match res {
                                    Ok(_) => {
                                        log::info!(
                                            "Finished dispatching call from host: {}",
                                            function_name
                                        );
                                        from_handler_tx
                                            .send(HandlerMsg::FinishedHypervisorHandlerAction)
                                            .map_err(|_| {
                                                HyperlightError::HypervisorHandlerCommunicationFailure()
                                            })?;
                                    }
                                    Err(e) => {
                                        log::info!(
                                            "Error dispatching call from host: {}: {:?}",
                                            function_name,
                                            e
                                        );
                                        from_handler_tx.send(HandlerMsg::Error(e)).map_err(|_| {
                                            HyperlightError::HypervisorHandlerCommunicationFailure()
                                        })?;
                                    }
                                }
                            }
                            HypervisorHandlerAction::TerminateHandlerThread => {
                                info!("Terminating Hypervisor Handler Thread");
                                break;
                            }
                        }
                    }

                    // If we make it here, it means the main thread issued a `TerminateHandlerThread` action,
                    // and we are now exiting the handler thread.
                    {
                        from_handler_tx
                            .send(HandlerMsg::FinishedHypervisorHandlerAction)
                            .map_err(|_| {
                                HyperlightError::HypervisorHandlerCommunicationFailure()
                            })?;
                    }

                    Ok(())
                })
        };

        self.execution_variables.set_join_handle(join_handle?)?;

        Ok(())
    }

    /// Try `join` on `HypervisorHandler` thread for `timeout` duration.
    /// - Before attempting a join, this function checks if execution isn't already finished.
    /// Note: This function call takes ownership of the `JoinHandle`.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    pub(crate) fn try_join_hypervisor_handler_thread(&mut self) -> Result<()> {
        let mut join_handle_guard = self
            .execution_variables
            .join_handle
            .try_lock()
            .map_err(|e| new_error!("Error locking at {}:{}: {}", file!(), line!(), e))?;
        if let Some(handle) = join_handle_guard.take() {
            // check if thread is handle.is_finished for `timeout`
            // note: dropping the transmitter in `kill_hypervisor_handler_thread`
            // should have caused the thread to finish, in here, we are just syncing.
            let now = std::time::Instant::now();

            while now.elapsed() < self.execution_variables.get_timeout()? {
                if handle.is_finished() {
                    match handle.join() {
                        // as per docs, join should return immediately and not hang if finished
                        Ok(Ok(())) => return Ok(()),
                        Ok(Err(e)) => {
                            log_then_return!(e);
                        }
                        Err(e) => {
                            log_then_return!(new_error!("{:?}", e));
                        }
                    }
                }
                sleep(Duration::from_millis(1)); // sleep to not busy wait
            }
        }

        return Err(HyperlightError::Error(
            "Failed to finish Hypervisor handler thread".to_string(),
        ));
    }

    /// Tries to kill the Hypervisor Handler Thread.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    pub(crate) fn kill_hypervisor_handler_thread(&mut self) -> Result<()> {
        log::debug!("Killing Hypervisor Handler Thread");
        self.execute_hypervisor_handler_action(HypervisorHandlerAction::TerminateHandlerThread)?;

        self.try_join_hypervisor_handler_thread()
    }

    /// Send a message to the Hypervisor Handler and wait for a response.
    ///
    /// This function should be used for most interactions with the Hypervisor
    /// Handler.
    pub(crate) fn execute_hypervisor_handler_action(
        &mut self,
        hypervisor_handler_action: HypervisorHandlerAction,
    ) -> Result<()> {
        log::debug!(
            "Sending Hypervisor Handler Action: {:?}",
            hypervisor_handler_action
        );

        match hypervisor_handler_action {
            HypervisorHandlerAction::Initialise => self
                .execution_variables
                .set_timeout(self.configuration.max_init_time)?,
            HypervisorHandlerAction::DispatchCallFromHost(_) => self
                .execution_variables
                .set_timeout(self.configuration.max_exec_time)?,
            HypervisorHandlerAction::TerminateHandlerThread => self
                .execution_variables
                .set_timeout(self.configuration.max_init_time)?,
            // note: terminate can never hang, so setting the timeout for it is just
            // for completion of the match statement, and it is not really needed for
            // `TerminateHandlerThread`.
        }

        self.communication_channels
            .to_handler_tx
            .send(hypervisor_handler_action)
            .map_err(|_| HyperlightError::HypervisorHandlerCommunicationFailure())?;

        log::debug!("Waiting for Hypervisor Handler Response");

        self.try_receive_handler_msg()
    }

    /// Try to receive a `HandlerMsg` from the Hypervisor Handler Thread.
    ///
    /// Usually, you should use `execute_hypervisor_handler_action` to send and instantly
    /// try to receive a message.
    ///
    /// This function is only useful when we time out, handle a timeout,
    /// and still have to receive after sorting that out without sending
    /// an extra message.
    pub(crate) fn try_receive_handler_msg(&self) -> Result<()> {
        // When gdb debugging is enabled, we don't want to timeout on receiving messages
        // from the handler thread, as the thread may be paused by gdb.
        // In this case, we will wait indefinitely for a message from the handler thread.
        // Note: This applies to all the running sandboxes, not just the one being debugged.
        #[cfg(gdb)]
        let response = self.communication_channels.from_handler_rx.recv();
        #[cfg(not(gdb))]
        let response = self
            .communication_channels
            .from_handler_rx
            .recv_timeout(self.execution_variables.get_timeout()?);

        match response {
            Ok(msg) => match msg {
                HandlerMsg::Error(e) => Err(e),
                HandlerMsg::FinishedHypervisorHandlerAction => Ok(()),
            },
            Err(_) => {
                // If we have timed out it may be that the handler thread returned an error before it sent a message, so rather than just timeout here
                // we will try and get the join handle for the thread and if it has finished check to see if it returned an error
                // if it did then we will return that error, otherwise we will return the timeout error
                // we need to take ownership of the handle to join it
                match self
                    .execution_variables
                    .join_handle
                    .try_lock()
                    .map_err(|_| HyperlightError::HypervisorHandlerMessageReceiveTimedout())?
                    .take_if(|handle| handle.is_finished())
                {
                    Some(handle) => {
                        // If the thread has finished, we try to join it and return the error if it has one
                        let res = handle.join();
                        if res.as_ref().is_ok_and(|inner_res| inner_res.is_err()) {
                            return Err(res.unwrap().unwrap_err());
                        }
                        Err(HyperlightError::HypervisorHandlerMessageReceiveTimedout())
                    }
                    None => Err(HyperlightError::HypervisorHandlerMessageReceiveTimedout()),
                }
            }
        }
    }

    /// Terminate the execution of the hypervisor handler
    ///
    /// This function is intended to be called after a guest function called has
    /// timed-out (i.e., `from_handler_rx.recv_timeout(timeout).is_err()`).
    ///
    /// It is possible that, even after we timed-out, the guest function execution will
    /// finish. If that is the case, this function is fundamentally a NOOP, because it
    /// will restore the memory snapshot to the last state, and then re-initialise the
    /// accidentally terminated vCPU.
    ///
    /// This function, usually, will return one of the following HyperlightError's
    /// - `ExecutionCanceledByHost` if the execution was successfully terminated, or
    /// - `HypervisorHandlerExecutionCancelAttemptOnFinishedExecution` if the execution
    ///   finished while we tried to terminate it.
    ///
    /// Hence, common usage of this function would be to match on the result. If you get a
    /// `HypervisorHandlerExecutionCancelAttemptOnFinishedExecution`, you can safely ignore
    /// retrieve the return value from shared memory.
    pub(crate) fn terminate_hypervisor_handler_execution_and_reinitialise(
        &mut self,
        sandbox_memory_manager: &mut SandboxMemoryManager<HostSharedMemory>,
    ) -> Result<HyperlightError> {
        {
            if !self.execution_variables.running.load(Ordering::SeqCst) {
                info!("Execution finished while trying to cancel it");
                return Ok(HypervisorHandlerExecutionCancelAttemptOnFinishedExecution());
            } else {
                self.terminate_execution()?;
            }
        }

        {
            sleep(self.configuration.max_wait_for_cancellation);
            // check if still running
            if self.execution_variables.running.load(Ordering::SeqCst) {
                // If we still fail to acquire the hv_lock, this means that
                // we had actually timed-out on a host function call as the
                // `WHvCancelRunVirtualProcessor` didn't unlock.

                log::info!("Tried to cancel guest execution on host function call");
                return Err(GuestExecutionHungOnHostFunctionCall());
            }
        }

        // Receive `ExecutionCancelledByHost` or other
        let res = match self.try_receive_handler_msg() {
            Ok(_) => Ok(new_error!(
                "Expected ExecutionCanceledByHost, but received FinishedHypervisorHandlerAction"
            )),
            Err(e) => match e {
                HyperlightError::ExecutionCanceledByHost() => {
                    Ok(HyperlightError::ExecutionCanceledByHost())
                }
                _ => Ok(new_error!(
                    "Expected ExecutionCanceledByHost, but received: {:?}",
                    e
                )),
            },
        };

        // We cancelled execution, so we restore the state to what it was prior to the bad state
        // that caused the timeout.
        sandbox_memory_manager.restore_state_from_last_snapshot()?;

        // Re-initialise the vCPU.
        // This is 100% needed because, otherwise, all it takes to cause a DoS is for a
        // function to timeout as the vCPU will be in a bad state without re-init.
        log::debug!("Re-initialising vCPU");
        self.execute_hypervisor_handler_action(HypervisorHandlerAction::Initialise)?;

        res
    }

    pub(crate) fn set_dispatch_function_addr(
        &mut self,
        dispatch_function_addr: RawPtr,
    ) -> Result<()> {
        *self
            .configuration
            .dispatch_function_addr
            .try_lock()
            .map_err(|_| new_error!("Failed to set_dispatch_function_addr"))? =
            Some(dispatch_function_addr);

        Ok(())
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    pub(crate) fn terminate_execution(&self) -> Result<()> {
        error!(
            "Execution timed out after {} milliseconds , cancelling execution",
            self.execution_variables.get_timeout()?.as_millis()
        );

        #[cfg(target_os = "linux")]
        {
            let thread_id = self.execution_variables.get_thread_id()?;
            if thread_id == u64::MAX {
                log_then_return!("Failed to get thread id to signal thread");
            }
            let mut count: i32 = 0;
            // We need to send the signal multiple times in case the thread was between checking if it
            // should be cancelled and entering the run loop

            // We cannot do this forever (if the thread is calling a host function that never
            // returns we will sit here forever), so use the timeout_wait_to_cancel to limit the number
            // of iterations

            let number_of_iterations =
                self.configuration.max_wait_for_cancellation.as_micros() / 500;

            while !self.execution_variables.run_cancelled.load() {
                count += 1;

                if count > number_of_iterations.try_into().unwrap() {
                    break;
                }

                info!(
                    "Sending signal to thread {} iteration: {}",
                    thread_id, count
                );

                let ret = unsafe { pthread_kill(thread_id, SIGRTMIN()) };
                // We may get ESRCH if we try to signal a thread that has already exited
                if ret < 0 && ret != ESRCH {
                    log_then_return!("error {} calling pthread_kill", ret);
                }
                std::thread::sleep(Duration::from_micros(500));
            }
            if !self.execution_variables.run_cancelled.load() {
                log_then_return!(GuestExecutionHungOnHostFunctionCall());
            }
        }
        #[cfg(target_os = "windows")]
        {
            if self.execution_variables.get_partition_handle()?.is_some() {
                // partition handle only set when running in-hypervisor (not in-process)
                unsafe {
                    WHvCancelRunVirtualProcessor(
                        self.execution_variables.get_partition_handle()?.unwrap(), // safe unwrap
                        0,
                        0,
                    )
                    .map_err(|e| new_error!("Failed to cancel guest execution {:?}", e))?;
                }
            }
            // if running in-process on windows, we currently have no way of cancelling the execution
        }

        Ok(())
    }
}

/// `HypervisorHandlerActions` enumerates the
/// possible actions that a Hypervisor
/// handler can execute.
pub enum HypervisorHandlerAction {
    /// Initialise the vCPU
    Initialise,
    /// Execute a function call (String = name) from the host
    DispatchCallFromHost(String),
    /// Terminate hypervisor handler thread
    TerminateHandlerThread,
}

// Debug impl for HypervisorHandlerAction:
// - just prints the enum variant type name.
impl std::fmt::Debug for HypervisorHandlerAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HypervisorHandlerAction::Initialise => write!(f, "Initialise"),
            HypervisorHandlerAction::DispatchCallFromHost(_) => write!(f, "DispatchCallFromHost"),
            HypervisorHandlerAction::TerminateHandlerThread => write!(f, "TerminateHandlerThread"),
        }
    }
}

/// `HandlerMsg` is structure used by the Hypervisor
/// handler to indicate that the Hypervisor Handler has
/// finished performing an action (i.e., `DispatchCallFromHost`, or
/// `Initialise`).
pub enum HandlerMsg {
    FinishedHypervisorHandlerAction,
    Error(HyperlightError),
}

fn set_up_hypervisor_partition(
    mgr: &mut SandboxMemoryManager<GuestSharedMemory>,
    #[allow(unused_variables)] // parameter only used for in-process mode
    outb_handler: OutBHandlerWrapper,
    #[cfg(gdb)] debug_info: &Option<DebugInfo>,
) -> Result<Box<dyn Hypervisor>> {
    let mem_size = u64::try_from(mgr.shared_mem.mem_size())?;
    let mut regions = mgr.layout.get_memory_regions(&mgr.shared_mem)?;
    let rsp_ptr = {
        let rsp_u64 = mgr.set_up_shared_memory(mem_size, &mut regions)?;
        let rsp_raw = RawPtr::from(rsp_u64);
        GuestPtr::try_from(rsp_raw)
    }?;
    let base_ptr = GuestPtr::try_from(Offset::from(0))?;
    let pml4_ptr = {
        let pml4_offset_u64 = u64::try_from(SandboxMemoryLayout::PML4_OFFSET)?;
        base_ptr + Offset::from(pml4_offset_u64)
    };
    let entrypoint_ptr = {
        let entrypoint_total_offset = mgr.load_addr.clone() + mgr.entrypoint_offset;
        GuestPtr::try_from(entrypoint_total_offset)
    }?;

    if base_ptr != pml4_ptr {
        log_then_return!(
            "Error: base_ptr ({:#?}) does not equal pml4_ptr ({:#?})",
            base_ptr,
            pml4_ptr
        );
    }
    if entrypoint_ptr <= pml4_ptr {
        log_then_return!(
            "Error: entrypoint_ptr ({:#?}) is not greater than pml4_ptr ({:#?})",
            entrypoint_ptr,
            pml4_ptr
        );
    }
    if mgr.is_in_process() {
        cfg_if::cfg_if! {
            if #[cfg(inprocess)] {
                // in-process feature + debug build
                use super::inprocess::InprocessArgs;
                use crate::sandbox::leaked_outb::LeakedOutBWrapper;
                use super::inprocess::InprocessDriver;

                let leaked_outb_wrapper = LeakedOutBWrapper::new(mgr, outb_handler)?;
                let hv = InprocessDriver::new(InprocessArgs {
                    entrypoint_raw: u64::from(mgr.load_addr.clone() + mgr.entrypoint_offset),
                    peb_ptr_raw: mgr
                        .get_in_process_peb_address(mgr.shared_mem.base_addr() as u64)?,
                    leaked_outb_wrapper,
                })?;
                Ok(Box::new(hv))
            } else if #[cfg(inprocess)]{
                // in-process feature, but not debug build
                log_then_return!("In-process mode is only available on debug-builds");
            } else if #[cfg(debug_assertions)] {
                // debug build without in-process feature
                log_then_return!("In-process mode requires `inprocess` cargo feature");
            } else {
                log_then_return!("In-process mode requires `inprocess` cargo feature and is only available on debug-builds");
            }
        }
    } else {
        // Create gdb thread if gdb is enabled and the configuration is provided
        // This is only done when the hypervisor is not in-process
        #[cfg(gdb)]
        let gdb_conn = if let Some(DebugInfo { port }) = debug_info {
            let gdb_conn = create_gdb_thread(*port, unsafe { pthread_self() });

            // in case the gdb thread creation fails, we still want to continue
            // without gdb
            match gdb_conn {
                Ok(gdb_conn) => Some(gdb_conn),
                Err(e) => {
                    log::error!("Could not create gdb connection: {:#}", e);

                    None
                }
            }
        } else {
            None
        };

        match *get_available_hypervisor() {
            #[cfg(mshv)]
            Some(HypervisorType::Mshv) => {
                let hv = crate::hypervisor::hyperv_linux::HypervLinuxDriver::new(
                    regions,
                    entrypoint_ptr,
                    rsp_ptr,
                    pml4_ptr,
                )?;
                Ok(Box::new(hv))
            }

            #[cfg(kvm)]
            Some(HypervisorType::Kvm) => {
                let hv = crate::hypervisor::kvm::KVMDriver::new(
                    regions,
                    pml4_ptr.absolute()?,
                    entrypoint_ptr.absolute()?,
                    rsp_ptr.absolute()?,
                    #[cfg(gdb)]
                    gdb_conn,
                )?;
                Ok(Box::new(hv))
            }

            #[cfg(target_os = "windows")]
            Some(HypervisorType::Whp) => {
                let mmap_file_handle = mgr
                    .shared_mem
                    .with_exclusivity(|e| e.get_mmap_file_handle())?;
                let hv = crate::hypervisor::hyperv_windows::HypervWindowsDriver::new(
                    regions,
                    mgr.shared_mem.raw_mem_size(), // we use raw_* here because windows driver requires 64K aligned addresses,
                    mgr.shared_mem.raw_ptr() as *mut c_void, // and instead convert it to base_addr where needed in the driver itself
                    pml4_ptr.absolute()?,
                    entrypoint_ptr.absolute()?,
                    rsp_ptr.absolute()?,
                    HandleWrapper::from(mmap_file_handle),
                )?;
                Ok(Box::new(hv))
            }

            _ => {
                log_then_return!(NoHypervisorFound());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};
    use std::thread;

    use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterValue, ReturnType};
    use hyperlight_testing::simple_guest_as_string;

    #[cfg(target_os = "windows")]
    use crate::sandbox::SandboxConfiguration;
    use crate::sandbox::WrapperGetter;
    use crate::sandbox_state::sandbox::EvolvableSandbox;
    use crate::sandbox_state::transition::Noop;
    use crate::HyperlightError::HypervisorHandlerExecutionCancelAttemptOnFinishedExecution;
    use crate::{
        is_hypervisor_present, GuestBinary, HyperlightError, MultiUseSandbox, Result,
        UninitializedSandbox,
    };

    fn create_multi_use_sandbox() -> MultiUseSandbox {
        if !is_hypervisor_present() {
            panic!("Panic on create_multi_use_sandbox because no hypervisor is present");
        }

        // Tests that use this function seem to fail with timeouts sporadically on windows so timeouts are raised here

        let cfg = {
            #[cfg(target_os = "windows")]
            {
                let mut cfg = SandboxConfiguration::default();
                cfg.set_max_initialization_time(std::time::Duration::from_secs(10));
                cfg.set_max_execution_time(std::time::Duration::from_secs(3));
                Some(cfg)
            }
            #[cfg(not(target_os = "windows"))]
            {
                None
            }
        };

        let usbox = UninitializedSandbox::new(
            GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
            cfg,
            None,
            None,
        )
        .unwrap();

        usbox.evolve(Noop::default()).unwrap()
    }

    #[test]
    #[ignore] // this test runs by itself because it uses a lot of system resources
    fn create_1000_sandboxes() {
        let barrier = Arc::new(Barrier::new(21));

        let mut handles = vec![];

        for _ in 0..20 {
            let c = barrier.clone();

            let handle = thread::spawn(move || {
                c.wait();

                for _ in 0..50 {
                    create_multi_use_sandbox();
                }
            });

            handles.push(handle);
        }

        barrier.wait();

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn create_10_sandboxes() {
        for _ in 0..10 {
            create_multi_use_sandbox();
        }
    }

    #[test]
    fn hello_world() -> Result<()> {
        let mut sandbox = create_multi_use_sandbox();

        let msg = "Hello, World!\n".to_string();
        let res = sandbox.call_guest_function_by_name(
            "PrintOutput",
            ReturnType::Int,
            Some(vec![ParameterValue::String(msg.clone())]),
        );

        assert!(res.is_ok());

        Ok(())
    }

    #[test]
    fn terminate_execution_then_call_another_function() -> Result<()> {
        let mut sandbox = create_multi_use_sandbox();

        let res = sandbox.call_guest_function_by_name("Spin", ReturnType::Void, None);

        assert!(res.is_err());

        match res.err().unwrap() {
            HyperlightError::ExecutionCanceledByHost() => {}
            _ => panic!("Expected ExecutionTerminated error"),
        }

        let res = sandbox.call_guest_function_by_name(
            "Echo",
            ReturnType::String,
            Some(vec![ParameterValue::String("a".to_string())]),
        );

        assert!(res.is_ok());

        Ok(())
    }

    #[test]
    fn terminate_execution_of_an_already_finished_function_then_call_another_function() -> Result<()>
    {
        let call_print_output = |sandbox: &mut MultiUseSandbox| {
            let msg = "Hello, World!\n".to_string();
            let res = sandbox.call_guest_function_by_name(
                "PrintOutput",
                ReturnType::Int,
                Some(vec![ParameterValue::String(msg.clone())]),
            );

            assert!(res.is_ok());
        };

        let mut sandbox = create_multi_use_sandbox();
        call_print_output(&mut sandbox);

        // this simulates what would happen if a function actually successfully
        // finished while we attempted to terminate execution
        {
            match sandbox
                .get_hv_handler()
                .clone()
                .terminate_hypervisor_handler_execution_and_reinitialise(
                    sandbox.get_mgr_wrapper_mut().unwrap_mgr_mut(),
                )? {
                HypervisorHandlerExecutionCancelAttemptOnFinishedExecution() => {}
                _ => panic!("Expected error demonstrating execution wasn't cancelled properly"),
            }
        }

        call_print_output(&mut sandbox);
        call_print_output(&mut sandbox);

        Ok(())
    }
}
