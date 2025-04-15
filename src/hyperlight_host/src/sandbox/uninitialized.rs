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

use std::fmt::Debug;
use std::sync::{Arc, Mutex};

use log::LevelFilter;
use tracing::{instrument, Span};

#[cfg(gdb)]
use super::config::DebugInfo;
use super::uninitialized_evolve::evolve_impl_multi_use;
use crate::mem::mgr::SandboxMemoryManager;
use crate::mem::shared_mem::ExclusiveSharedMemory;
use crate::sandbox::host_funcs::HostFuncsWrapper;
use crate::sandbox::SandboxConfiguration;
use crate::sandbox_state::sandbox::{EvolvableSandbox, Sandbox};
use crate::sandbox_state::transition::Noop;
use crate::{log_then_return, MultiUseSandbox, Result};

/// A preliminary `Sandbox`, not yet ready to execute guest code.
///
/// Prior to initializing a full-fledged sandbox, you must create a
/// `UninitializedSandbox` with the `new` function, register all the
/// host-implemented functions you need to be available to the guest, then
/// call  `evolve` to transform your `UninitializedSandbox` into an initialized
/// sandbox.
pub struct UninitializedSandbox {
    pub(crate) host_funcs: Arc<Mutex<HostFuncsWrapper>>,
    pub(crate) mem_mgr: SandboxMemoryManager<ExclusiveSharedMemory>,
    pub(crate) config: SandboxConfiguration,
    pub(crate) max_guest_log_level: Option<LevelFilter>,
    #[cfg(gdb)]
    pub(crate) debug_info: Option<DebugInfo>,
}

impl Debug for UninitializedSandbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UninitializedSandbox")
            .field("Memory Layout", &self.mem_mgr.memory_sections)
            .finish()
    }
}

impl Sandbox for UninitializedSandbox {
    fn check_stack_guard(&self) -> Result<bool> {
        log_then_return!(
            "Checking the stack cookie before the sandbox is initialized is unsupported"
        );
    }
}

impl
    EvolvableSandbox<
        UninitializedSandbox,
        MultiUseSandbox,
        Noop<UninitializedSandbox, MultiUseSandbox>,
    > for UninitializedSandbox
{
    /// Evolve `self` to a `MultiUseSandbox` without any additional metadata.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    fn evolve(self, _: Noop<UninitializedSandbox, MultiUseSandbox>) -> Result<MultiUseSandbox> {
        evolve_impl_multi_use(self)
    }
}

impl UninitializedSandbox {
    /// Create a new uninitialized sandbox.
    pub(crate) fn new(
        mem_mgr: SandboxMemoryManager<ExclusiveSharedMemory>,
        config: SandboxConfiguration,
        #[cfg(gdb)] debug_info: Option<DebugInfo>,
    ) -> Self {
        Self {
            host_funcs: Arc::new(Mutex::new(HostFuncsWrapper::default())),
            mem_mgr,
            config,
            max_guest_log_level: None,
            #[cfg(gdb)]
            debug_info,
        }
    }

    /// Set the max log level to be used by the guest.
    /// If this is not set then the log level will be determined by parsing the RUST_LOG environment variable.
    /// If the RUST_LOG environment variable is not set then the max log level will be set to `LevelFilter::Error`.
    pub fn set_max_guest_log_level(&mut self, log_level: LevelFilter) {
        self.max_guest_log_level = Some(log_level);
    }
}

// Check to see if the current version of Windows is supported
// Hyperlight is only supported on Windows 11 and Windows Server 2022 and later
#[cfg(target_os = "windows")]
fn check_windows_version() -> Result<()> {
    use windows_version::{is_server, OsVersion};
    const WINDOWS_MAJOR: u32 = 10;
    const WINDOWS_MINOR: u32 = 0;
    const WINDOWS_PACK: u32 = 0;

    // Windows Server 2022 has version numbers 10.0.20348 or greater
    if is_server() {
        if OsVersion::current() < OsVersion::new(WINDOWS_MAJOR, WINDOWS_MINOR, WINDOWS_PACK, 20348)
        {
            return Err(new_error!(
                "Hyperlight Requires Windows Server 2022 or newer"
            ));
        }
    } else if OsVersion::current()
        < OsVersion::new(WINDOWS_MAJOR, WINDOWS_MINOR, WINDOWS_PACK, 22000)
    {
        return Err(new_error!("Hyperlight Requires Windows 11 or newer"));
    }
    Ok(())
}

// TODO(danbugs:297): bring back tests
// #[cfg(test)]
// mod tests {
//     use std::path::PathBuf;
//     use std::sync::{Arc, Mutex};
//     use std::time::Duration;
//     use std::{fs, thread};
//
//     use crossbeam_queue::ArrayQueue;
//     use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterValue, ReturnValue};
//     use hyperlight_testing::logger::{Logger as TestLogger, LOGGER as TEST_LOGGER};
//     use hyperlight_testing::tracing_subscriber::TracingSubscriber as TestSubscriber;
//     use hyperlight_testing::{simple_guest_as_string, simple_guest_exe_as_string};
//     use log::Level;
//     use serde_json::{Map, Value};
//     use serial_test::serial;
//     use tracing::Level as tracing_level;
//     use tracing_core::callsite::rebuild_interest_cache;
//     use tracing_core::Subscriber;
//     use uuid::Uuid;
//
//     use crate::func::{HostFunction1, HostFunction2};
//     use crate::sandbox::uninitialized::GuestBinary;
//     use crate::sandbox::SandboxConfiguration;
//     use crate::sandbox_state::sandbox::EvolvableSandbox;
//     use crate::sandbox_state::transition::Noop;
//     use crate::testing::log_values::{test_value_as_str, try_to_strings};
//     use crate::{new_error, MultiUseSandbox, Result, SandboxRunOptions, UninitializedSandbox};
//
//     #[test]
//     fn test_in_process() {
//         let simple_guest_path = simple_guest_as_string().unwrap();
//         let sbox = UninitializedSandbox::new(
//             GuestBinary::FilePath(simple_guest_path.clone()),
//             None,
//             Some(SandboxRunOptions::RunInProcess(false)),
//             None,
//         );
//
//         // in process should only be enabled with the inprocess feature and on debug builds
//         assert_eq!(sbox.is_ok(), cfg!(inprocess));
//
//         let sbox = UninitializedSandbox::new(
//             GuestBinary::FilePath(simple_guest_path.clone()),
//             None,
//             Some(SandboxRunOptions::RunInProcess(true)),
//             None,
//         );
//
//         // debug mode should fail with an elf executable
//         assert!(sbox.is_err());
//
//         let simple_guest_path = simple_guest_exe_as_string().unwrap();
//         let sbox = UninitializedSandbox::new(
//             GuestBinary::FilePath(simple_guest_path.clone()),
//             None,
//             Some(SandboxRunOptions::RunInProcess(false)),
//             None,
//         );
//
//         // in process should only be enabled with the inprocess feature and on debug builds
//         assert_eq!(sbox.is_ok(), cfg!(all(inprocess)));
//
//         let sbox = UninitializedSandbox::new(
//             GuestBinary::FilePath(simple_guest_path.clone()),
//             None,
//             Some(SandboxRunOptions::RunInProcess(true)),
//             None,
//         );
//
//         // debug mode should succeed with a PE executable on windows with inprocess enabled
//         assert_eq!(sbox.is_ok(), cfg!(all(inprocess, target_os = "windows")));
//     }
//
//     #[test]
//     fn test_new_sandbox() {
//         // Guest Binary exists at path
//
//         let binary_path = simple_guest_as_string().unwrap();
//         let sandbox =
//             UninitializedSandbox::new(GuestBinary::FilePath(binary_path.clone()), None, None, None);
//         assert!(sandbox.is_ok());
//
//         // Guest Binary does not exist at path
//
//         let mut binary_path_does_not_exist = binary_path.clone();
//         binary_path_does_not_exist.push_str(".nonexistent");
//         let uninitialized_sandbox = UninitializedSandbox::new(
//             GuestBinary::FilePath(binary_path_does_not_exist),
//             None,
//             None,
//             None,
//         );
//         assert!(uninitialized_sandbox.is_err());
//
//         // Non default memory configuration
//         let cfg = {
//             let mut cfg = SandboxConfiguration::default();
//             cfg.set_input_data_size(0x1000);
//             cfg.set_output_data_size(0x1000);
//             cfg.set_host_function_definition_size(0x1000);
//             cfg.set_host_exception_size(0x1000);
//             cfg.set_guest_error_buffer_size(0x1000);
//             cfg.set_stack_size(0x1000);
//             cfg.set_heap_size(0x1000);
//             cfg.set_max_execution_time(Duration::from_millis(1001));
//             cfg.set_max_execution_cancel_wait_time(Duration::from_millis(9));
//             Some(cfg)
//         };
//
//         let uninitialized_sandbox =
//             UninitializedSandbox::new(GuestBinary::FilePath(binary_path.clone()), cfg, None, None);
//         assert!(uninitialized_sandbox.is_ok());
//
//         let uninitialized_sandbox =
//             UninitializedSandbox::new(GuestBinary::FilePath(binary_path), None, None, None)
//                 .unwrap();
//
//         // Get a Sandbox from an uninitialized sandbox without a call back function
//
//         let _sandbox: MultiUseSandbox = uninitialized_sandbox.evolve(Noop::default()).unwrap();
//
//         // Test with a valid guest binary buffer
//
//         let binary_path = simple_guest_as_string().unwrap();
//         let sandbox = UninitializedSandbox::new(
//             GuestBinary::Buffer(fs::read(binary_path).unwrap()),
//             None,
//             None,
//             None,
//         );
//         assert!(sandbox.is_ok());
//
//         // Test with a invalid guest binary buffer
//
//         let binary_path = simple_guest_as_string().unwrap();
//         let mut bytes = fs::read(binary_path).unwrap();
//         let _ = bytes.split_off(100);
//         let sandbox = UninitializedSandbox::new(GuestBinary::Buffer(bytes), None, None, None);
//         assert!(sandbox.is_err());
//
//         // Test with a valid guest binary buffer when trying to load library
//         #[cfg(target_os = "windows")]
//         {
//             let binary_path = simple_guest_as_string().unwrap();
//             let sandbox = UninitializedSandbox::new(
//                 GuestBinary::Buffer(fs::read(binary_path).unwrap()),
//                 None,
//                 Some(SandboxRunOptions::RunInProcess(true)),
//                 None,
//             );
//             assert!(sandbox.is_err());
//         }
//     }
//
//     #[test]
//     fn test_load_guest_binary_manual() {
//         let cfg = SandboxConfiguration::default();
//
//         let simple_guest_path = simple_guest_as_string().unwrap();
//
//         UninitializedSandbox::load_guest_binary(
//             cfg,
//             &GuestBinary::FilePath(simple_guest_path),
//             false,
//             false,
//         )
//             .unwrap();
//     }
//
//     #[test]
//     fn test_host_functions() {
//         let uninitialized_sandbox = || {
//             UninitializedSandbox::new(
//                 GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
//                 None,
//                 None,
//                 None,
//             )
//                 .unwrap()
//         };
//
//         // simple register + call
//         {
//             let mut usbox = uninitialized_sandbox();
//             let test0 = |arg: i32| -> Result<i32> { Ok(arg + 1) };
//             let test_func0 = Arc::new(Mutex::new(test0));
//             test_func0.register(&mut usbox, "test0").unwrap();
//
//             let sandbox: Result<MultiUseSandbox> = usbox.evolve(Noop::default());
//             assert!(sandbox.is_ok());
//             let sandbox = sandbox.unwrap();
//
//             let host_funcs = sandbox
//                 ._host_funcs
//                 .try_lock()
//                 .map_err(|_| new_error!("Error locking"));
//
//             assert!(host_funcs.is_ok());
//
//             let res = host_funcs
//                 .unwrap()
//                 .call_host_function("test0", vec![ParameterValue::Int(1)])
//                 .unwrap();
//
//             assert_eq!(res, ReturnValue::Int(2));
//         }
//
//         // multiple parameters register + call
//         {
//             let mut usbox = uninitialized_sandbox();
//             let test1 = |arg1: i32, arg2: i32| -> Result<i32> { Ok(arg1 + arg2) };
//             let test_func1 = Arc::new(Mutex::new(test1));
//             test_func1.register(&mut usbox, "test1").unwrap();
//
//             let sandbox: Result<MultiUseSandbox> = usbox.evolve(Noop::default());
//             assert!(sandbox.is_ok());
//             let sandbox = sandbox.unwrap();
//
//             let host_funcs = sandbox
//                 ._host_funcs
//                 .try_lock()
//                 .map_err(|_| new_error!("Error locking"));
//
//             assert!(host_funcs.is_ok());
//
//             let res = host_funcs
//                 .unwrap()
//                 .call_host_function(
//                     "test1",
//                     vec![ParameterValue::Int(1), ParameterValue::Int(2)],
//                 )
//                 .unwrap();
//
//             assert_eq!(res, ReturnValue::Int(3));
//         }
//
//         // incorrect arguments register + call
//         {
//             let mut usbox = uninitialized_sandbox();
//             let test2 = |arg1: String| -> Result<()> {
//                 println!("test2 called: {}", arg1);
//                 Ok(())
//             };
//             let test_func2 = Arc::new(Mutex::new(test2));
//             test_func2.register(&mut usbox, "test2").unwrap();
//
//             let sandbox: Result<MultiUseSandbox> = usbox.evolve(Noop::default());
//             assert!(sandbox.is_ok());
//             let sandbox = sandbox.unwrap();
//
//             let host_funcs = sandbox
//                 ._host_funcs
//                 .try_lock()
//                 .map_err(|_| new_error!("Error locking"));
//
//             assert!(host_funcs.is_ok());
//
//             let res = host_funcs.unwrap().call_host_function("test2", vec![]);
//             assert!(res.is_err());
//         }
//
//         // calling a function that doesn't exist
//         {
//             let usbox = uninitialized_sandbox();
//             let sandbox: Result<MultiUseSandbox> = usbox.evolve(Noop::default());
//             assert!(sandbox.is_ok());
//             let sandbox = sandbox.unwrap();
//
//             let host_funcs = sandbox
//                 ._host_funcs
//                 .try_lock()
//                 .map_err(|_| new_error!("Error locking"));
//
//             assert!(host_funcs.is_ok());
//
//             let res = host_funcs.unwrap().call_host_function("test4", vec![]);
//             assert!(res.is_err());
//         }
//     }
//
//     #[test]
//     #[serial]
//     fn test_load_guest_binary_load_lib() {
//         let cfg = SandboxConfiguration::default();
//         let simple_guest_path = simple_guest_exe_as_string().unwrap();
//         let mgr_res = UninitializedSandbox::load_guest_binary(
//             cfg,
//             &GuestBinary::FilePath(simple_guest_path),
//             true,
//             true,
//         );
//         #[cfg(target_os = "linux")]
//         {
//             assert!(mgr_res.is_err())
//         }
//         #[cfg(target_os = "windows")]
//         {
//             #[cfg(inprocess)]
//             {
//                 assert!(mgr_res.is_ok())
//             }
//             #[cfg(not(inprocess))]
//             {
//                 assert!(mgr_res.is_err())
//             }
//         }
//     }
//
//     #[test]
//     fn test_host_print() {
//         // writer as a FnMut closure mutating a captured variable and then trying to access the captured variable
//         // after the Sandbox instance has been dropped
//         // this example is fairly contrived but we should still support such an approach.
//
//         let received_msg = Arc::new(Mutex::new(String::new()));
//         let received_msg_clone = received_msg.clone();
//
//         let writer = move |msg| {
//             let mut received_msg = received_msg_clone
//                 .try_lock()
//                 .map_err(|_| new_error!("Error locking"))
//                 .unwrap();
//             *received_msg = msg;
//             Ok(0)
//         };
//
//         let hostfunc = Arc::new(Mutex::new(writer));
//
//         let sandbox = UninitializedSandbox::new(
//             GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
//             None,
//             None,
//             Some(&hostfunc),
//         )
//             .expect("Failed to create sandbox");
//
//         let host_funcs = sandbox
//             .host_funcs
//             .try_lock()
//             .map_err(|_| new_error!("Error locking"));
//
//         assert!(host_funcs.is_ok());
//
//         host_funcs.unwrap().host_print("test".to_string()).unwrap();
//
//         drop(sandbox);
//
//         assert_eq!(
//             received_msg
//                 .try_lock()
//                 .map_err(|_| new_error!("Error locking"))
//                 .unwrap()
//                 .as_str(),
//             "test"
//         );
//
//         // There may be cases where a mutable reference to the captured variable is not required to be used outside the closue
//         // e.g. if the function is writing to a file or a socket etc.
//
//         // writer as a FnMut closure mutating a captured variable but not trying to access the captured variable
//
//         // This seems more realistic as the client is creating a file to be written to in the closure
//         // and then accessing the file a different handle.
//         // The problem is that captured_file still needs static lifetime so even though we can access the data through the second file handle
//         // this still does not work as the captured_file is dropped at the end of the function
//
//         // TODO: Currently, we block any writes that are not to
//         // the stdout/stderr file handles, so this code is commented
//         // out until we can register writer functions like any other
//         // host functions with their own set of extra allowed syscalls.
//         // In particular, this code should be brought back once we have addressed the issue
//
//         // let captured_file = Arc::new(Mutex::new(NamedTempFile::new().unwrap()));
//         // let capture_file_clone = captured_file.clone();
//         //
//         // let capture_file_lock = captured_file
//         //     .try_lock()
//         //     .map_err(|_| new_error!("Error locking"))
//         //     .unwrap();
//         // let mut file = capture_file_lock.reopen().unwrap();
//         // drop(capture_file_lock);
//         //
//         // let writer = move |msg: String| -> Result<i32> {
//         //     let mut captured_file = capture_file_clone
//         //         .try_lock()
//         //         .map_err(|_| new_error!("Error locking"))
//         //         .unwrap();
//         //     captured_file.write_all(msg.as_bytes()).unwrap();
//         //     Ok(0)
//         // };
//         //
//         // let writer_func = Arc::new(Mutex::new(writer));
//         //
//         // let sandbox = UninitializedSandbox::new(
//         //     GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
//         //     None,
//         //     None,
//         //     Some(&writer_func),
//         // )
//         // .expect("Failed to create sandbox");
//         //
//         // let host_funcs = sandbox
//         //     .host_funcs
//         //     .try_lock()
//         //     .map_err(|_| new_error!("Error locking"));
//         //
//         // assert!(host_funcs.is_ok());
//         //
//         // host_funcs.unwrap().host_print("test2".to_string()).unwrap();
//         //
//         // let mut buffer = String::new();
//         // file.read_to_string(&mut buffer).unwrap();
//         // assert_eq!(buffer, "test2");
//
//         // writer as a function
//
//         fn fn_writer(msg: String) -> Result<i32> {
//             assert_eq!(msg, "test2");
//             Ok(0)
//         }
//
//         let writer_func = Arc::new(Mutex::new(fn_writer));
//         let sandbox = UninitializedSandbox::new(
//             GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
//             None,
//             None,
//             Some(&writer_func),
//         )
//             .expect("Failed to create sandbox");
//
//         let host_funcs = sandbox
//             .host_funcs
//             .try_lock()
//             .map_err(|_| new_error!("Error locking"));
//
//         assert!(host_funcs.is_ok());
//
//         host_funcs.unwrap().host_print("test2".to_string()).unwrap();
//
//         // writer as a method
//
//         let mut test_host_print = TestHostPrint::new();
//
//         // create a closure over the struct method
//
//         let writer_closure = move |s| test_host_print.write(s);
//
//         let writer_method = Arc::new(Mutex::new(writer_closure));
//
//         let sandbox = UninitializedSandbox::new(
//             GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
//             None,
//             None,
//             Some(&writer_method),
//         )
//             .expect("Failed to create sandbox");
//
//         let host_funcs = sandbox
//             .host_funcs
//             .try_lock()
//             .map_err(|_| new_error!("Error locking"));
//
//         assert!(host_funcs.is_ok());
//
//         host_funcs.unwrap().host_print("test3".to_string()).unwrap();
//     }
//
//     struct TestHostPrint {}
//
//     impl TestHostPrint {
//         fn new() -> Self {
//             TestHostPrint {}
//         }
//
//         fn write(&mut self, msg: String) -> Result<i32> {
//             assert_eq!(msg, "test3");
//             Ok(0)
//         }
//     }
//
//     #[test]
//     fn check_create_and_use_sandbox_on_different_threads() {
//         let unintializedsandbox_queue = Arc::new(ArrayQueue::<UninitializedSandbox>::new(10));
//         let sandbox_queue = Arc::new(ArrayQueue::<MultiUseSandbox>::new(10));
//
//         for i in 0..10 {
//             let simple_guest_path = simple_guest_as_string().expect("Guest Binary Missing");
//             let unintializedsandbox = {
//                 let err_string = format!("failed to create UninitializedSandbox {i}");
//                 let err_str = err_string.as_str();
//                 UninitializedSandbox::new(
//                     GuestBinary::FilePath(simple_guest_path),
//                     None,
//                     None,
//                     None,
//                 )
//                     .expect(err_str)
//             };
//
//             {
//                 let err_string = format!("Failed to push UninitializedSandbox {i}");
//                 let err_str = err_string.as_str();
//
//                 unintializedsandbox_queue
//                     .push(unintializedsandbox)
//                     .expect(err_str);
//             }
//         }
//
//         let thread_handles = (0..10)
//             .map(|i| {
//                 let uq = unintializedsandbox_queue.clone();
//                 let sq = sandbox_queue.clone();
//                 thread::spawn(move || {
//                     let uninitialized_sandbox = uq.pop().unwrap_or_else(|| {
//                         panic!("Failed to pop UninitializedSandbox thread {}", i)
//                     });
//
//                     let host_funcs = uninitialized_sandbox
//                         .host_funcs
//                         .try_lock()
//                         .map_err(|_| new_error!("Error locking"));
//
//                     assert!(host_funcs.is_ok());
//
//                     host_funcs
//                         .unwrap()
//                         .host_print(format!("Print from UninitializedSandbox on Thread {}\n", i))
//                         .unwrap();
//
//                     let sandbox = uninitialized_sandbox
//                         .evolve(Noop::default())
//                         .unwrap_or_else(|_| {
//                             panic!("Failed to initialize UninitializedSandbox thread {}", i)
//                         });
//
//                     sq.push(sandbox).unwrap_or_else(|_| {
//                         panic!("Failed to push UninitializedSandbox thread {}", i)
//                     })
//                 })
//             })
//             .collect::<Vec<_>>();
//
//         for handle in thread_handles {
//             handle.join().unwrap();
//         }
//
//         let thread_handles = (0..10)
//             .map(|i| {
//                 let sq = sandbox_queue.clone();
//                 thread::spawn(move || {
//                     let sandbox = sq
//                         .pop()
//                         .unwrap_or_else(|| panic!("Failed to pop Sandbox thread {}", i));
//
//                     let host_funcs = sandbox
//                         ._host_funcs
//                         .try_lock()
//                         .map_err(|_| new_error!("Error locking"));
//
//                     assert!(host_funcs.is_ok());
//
//                     host_funcs
//                         .unwrap()
//                         .host_print(format!("Print from Sandbox on Thread {}\n", i))
//                         .unwrap();
//                 })
//             })
//             .collect::<Vec<_>>();
//
//         for handle in thread_handles {
//             handle.join().unwrap();
//         }
//     }
//
//     #[test]
//     // Tests that trace data are emitted when a trace subscriber is set
//     // this test is ignored because it is incompatible with other tests , specifically those which require a logger for tracing
//     // marking  this test as ignored means that running `cargo test` will not run this test but will allow a developer who runs that command
//     // from their workstation to be successful without needed to know about test interdependencies
//     // this test will be run explicitly as a part of the CI pipeline
//     #[ignore]
//     fn test_trace_trace() {
//         TestLogger::initialize_log_tracer();
//         rebuild_interest_cache();
//         let subscriber = TestSubscriber::new(tracing_level::TRACE);
//         tracing::subscriber::with_default(subscriber.clone(), || {
//             let correlation_id = Uuid::new_v4().as_hyphenated().to_string();
//             let span = tracing::error_span!("test_trace_logs", correlation_id).entered();
//
//             // We should be in span 1
//
//             let current_span = subscriber.current_span();
//             assert!(current_span.is_known(), "Current span is unknown");
//             let current_span_metadata = current_span.into_inner().unwrap();
//             assert_eq!(
//                 current_span_metadata.0.into_u64(),
//                 1,
//                 "Current span is not span 1"
//             );
//             assert_eq!(current_span_metadata.1.name(), "test_trace_logs");
//
//             // Get the span data and check the correlation id
//
//             let span_data = subscriber.get_span(1);
//             let span_attributes: &Map<String, Value> = span_data
//                 .get("span")
//                 .unwrap()
//                 .get("attributes")
//                 .unwrap()
//                 .as_object()
//                 .unwrap();
//
//             test_value_as_str(span_attributes, "correlation_id", correlation_id.as_str());
//
//             let mut binary_path = simple_guest_as_string().unwrap();
//             binary_path.push_str("does_not_exist");
//
//             let sbox =
//                 UninitializedSandbox::new(GuestBinary::FilePath(binary_path), None, None, None);
//             assert!(sbox.is_err());
//
//             // Now we should still be in span 1 but span 2 should be created (we created entered and exited span 2 when we called UninitializedSandbox::new)
//
//             let current_span = subscriber.current_span();
//             assert!(current_span.is_known(), "Current span is unknown");
//             let current_span_metadata = current_span.into_inner().unwrap();
//             assert_eq!(
//                 current_span_metadata.0.into_u64(),
//                 1,
//                 "Current span is not span 1"
//             );
//
//             let span_metadata = subscriber.get_span_metadata(2);
//             assert_eq!(span_metadata.name(), "new");
//
//             // There should be one event for the error that the binary path does not exist plus 14 info events for the logging of the crate info
//
//             let events = subscriber.get_events();
//             assert_eq!(events.len(), 15);
//
//             let mut count_matching_events = 0;
//
//             for json_value in events {
//                 let event_values = json_value.as_object().unwrap().get("event").unwrap();
//                 let metadata_values_map =
//                     event_values.get("metadata").unwrap().as_object().unwrap();
//                 let event_values_map = event_values.as_object().unwrap();
//
//                 let expected_error_start = "Error(\"GuestBinary not found:";
//
//                 let err_vals_res = try_to_strings([
//                     (metadata_values_map, "level"),
//                     (event_values_map, "error"),
//                     (metadata_values_map, "module_path"),
//                     (metadata_values_map, "target"),
//                 ]);
//                 if let Ok(err_vals) = err_vals_res {
//                     if err_vals[0] == "ERROR"
//                         && err_vals[1].starts_with(expected_error_start)
//                         && err_vals[2] == "hyperlight_host::sandbox::uninitialized"
//                         && err_vals[3] == "hyperlight_host::sandbox::uninitialized"
//                     {
//                         count_matching_events += 1;
//                     }
//                 }
//             }
//             assert!(
//                 count_matching_events == 1,
//                 "Unexpected number of matching events {}",
//                 count_matching_events
//             );
//             span.exit();
//             subscriber.clear();
//         });
//     }
//
//     #[test]
//     #[ignore]
//     // Tests that traces are emitted as log records when there is no trace
//     // subscriber configured.
//     fn test_log_trace() {
//         {
//             TestLogger::initialize_test_logger();
//             TEST_LOGGER.set_max_level(log::LevelFilter::Trace);
//
//             // This makes sure that the metadata interest cache is rebuilt so that
//             // the log records are emitted for the trace records
//
//             rebuild_interest_cache();
//
//             let mut invalid_binary_path = simple_guest_as_string().unwrap();
//             invalid_binary_path.push_str("does_not_exist");
//
//             let sbox = UninitializedSandbox::new(
//                 GuestBinary::FilePath(invalid_binary_path),
//                 None,
//                 None,
//                 None,
//             );
//             assert!(sbox.is_err());
//
//             // When tracing is creating log records it will create a log
//             // record for the creation of the span (from the instrument
//             // attribute), and will then create a log record for the entry to
//             // and exit from the span.
//             //
//             // It also creates a log record for the span being dropped.
//             //
//             // In addition there are 14 info log records created for build information
//             //
//             // So we expect 19 log records for this test, four for the span and
//             // then one for the error as the file that we are attempting to
//             // load into the sandbox does not exist, plus the 14 info log records
//
//             let num_calls = TEST_LOGGER.num_log_calls();
//             assert_eq!(19, num_calls);
//
//             // Log record 1
//
//             let logcall = TEST_LOGGER.get_log_call(0).unwrap();
//             assert_eq!(Level::Info, logcall.level);
//
//             assert!(logcall.args.starts_with("new; cfg"));
//             assert_eq!("hyperlight_host::sandbox::uninitialized", logcall.target);
//
//             // Log record 2
//
//             let logcall = TEST_LOGGER.get_log_call(1).unwrap();
//             assert_eq!(Level::Trace, logcall.level);
//             assert_eq!(logcall.args, "-> new;");
//             assert_eq!("tracing::span::active", logcall.target);
//
//             // Log record 17
//
//             let logcall = TEST_LOGGER.get_log_call(16).unwrap();
//             assert_eq!(Level::Error, logcall.level);
//             assert!(logcall
//                 .args
//                 .starts_with("error=Error(\"GuestBinary not found:"));
//             assert_eq!("hyperlight_host::sandbox::uninitialized", logcall.target);
//
//             // Log record 18
//
//             let logcall = TEST_LOGGER.get_log_call(17).unwrap();
//             assert_eq!(Level::Trace, logcall.level);
//             assert_eq!(logcall.args, "<- new;");
//             assert_eq!("tracing::span::active", logcall.target);
//
//             // Log record 19
//
//             let logcall = TEST_LOGGER.get_log_call(18).unwrap();
//             assert_eq!(Level::Trace, logcall.level);
//             assert_eq!(logcall.args, "-- new;");
//             assert_eq!("tracing::span", logcall.target);
//         }
//         {
//             // test to ensure an invalid binary logs & traces properly
//             TEST_LOGGER.clear_log_calls();
//             TEST_LOGGER.set_max_level(log::LevelFilter::Info);
//
//             let mut valid_binary_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
//             valid_binary_path.push("src");
//             valid_binary_path.push("sandbox");
//             valid_binary_path.push("initialized.rs");
//
//             let sbox = UninitializedSandbox::new(
//                 GuestBinary::FilePath(valid_binary_path.into_os_string().into_string().unwrap()),
//                 None,
//                 None,
//                 None,
//             );
//             assert!(sbox.is_err());
//
//             // There should be 2 calls this time when we change to the log
//             // LevelFilter to Info.
//             let num_calls = TEST_LOGGER.num_log_calls();
//             assert_eq!(2, num_calls);
//
//             // Log record 1
//
//             let logcall = TEST_LOGGER.get_log_call(0).unwrap();
//             assert_eq!(Level::Info, logcall.level);
//
//             assert!(logcall.args.starts_with("new; cfg"));
//             assert_eq!("hyperlight_host::sandbox::uninitialized", logcall.target);
//
//             // Log record 2
//
//             let logcall = TEST_LOGGER.get_log_call(1).unwrap();
//             assert_eq!(Level::Error, logcall.level);
//             assert!(logcall
//                 .args
//                 .starts_with("error=Error(\"GuestBinary not found:"));
//             assert_eq!("hyperlight_host::sandbox::uninitialized", logcall.target);
//         }
//         {
//             TEST_LOGGER.clear_log_calls();
//             TEST_LOGGER.set_max_level(log::LevelFilter::Error);
//
//             let sbox = {
//                 let res = UninitializedSandbox::new(
//                     GuestBinary::FilePath(simple_guest_as_string().unwrap()),
//                     None,
//                     None,
//                     None,
//                 );
//                 res.unwrap()
//             };
//             let _: Result<MultiUseSandbox> = sbox.evolve(Noop::default());
//
//             let num_calls = TEST_LOGGER.num_log_calls();
//
//             assert_eq!(0, num_calls);
//         }
//     }
//
//     #[test]
//     fn test_invalid_path() {
//         let invalid_path = "some/path/that/does/not/exist";
//         let sbox = UninitializedSandbox::new(
//             GuestBinary::FilePath(invalid_path.to_string()),
//             None,
//             None,
//             None,
//         );
//         println!("{:?}", sbox);
//         #[cfg(target_os = "windows")]
//         assert!(
//             matches!(sbox, Err(e) if e.to_string().contains("GuestBinary not found: 'some/path/that/does/not/exist': The system cannot find the path specified. (os error 3)"))
//         );
//         #[cfg(target_os = "linux")]
//         assert!(
//             matches!(sbox, Err(e) if e.to_string().contains("GuestBinary not found: 'some/path/that/does/not/exist': No such file or directory (os error 2)"))
//         );
//     }
// }
