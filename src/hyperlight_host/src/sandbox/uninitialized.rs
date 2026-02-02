/*
Copyright 2025  The Hyperlight Authors.

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
use std::option::Option;
use std::path::Path;
use std::sync::{Arc, Mutex};

use log::LevelFilter;
use tracing::{Span, instrument};

use super::host_funcs::{FunctionRegistry, default_writer_func};
use super::snapshot::Snapshot;
use super::uninitialized_evolve::evolve_impl_multi_use;
use crate::func::host_functions::{HostFunction, register_host_function};
use crate::func::{ParameterTuple, SupportedReturnType};
#[cfg(feature = "build-metadata")]
use crate::log_build_details;
use crate::mem::memory_region::{DEFAULT_GUEST_BLOB_MEM_FLAGS, MemoryRegionFlags};
use crate::mem::mgr::SandboxMemoryManager;
use crate::mem::shared_mem::ExclusiveSharedMemory;
use crate::sandbox::SandboxConfiguration;
use crate::{MultiUseSandbox, Result, new_error};

#[cfg(any(crashdump, gdb))]
#[derive(Clone, Debug, Default)]
pub(crate) struct SandboxRuntimeConfig {
    #[cfg(crashdump)]
    pub(crate) binary_path: Option<String>,
    #[cfg(gdb)]
    pub(crate) debug_info: Option<super::config::DebugInfo>,
    #[cfg(crashdump)]
    pub(crate) guest_core_dump: bool,
}

/// A preliminary sandbox that represents allocated memory and registered host functions,
/// but has not yet created the underlying virtual machine.
///
/// This struct holds the configuration and setup needed for a sandbox without actually
/// creating the VM. It allows you to:
/// - Set up memory layout and load guest binary data
/// - Register host functions that will be available to the guest
/// - Configure sandbox settings before VM creation
///
/// The virtual machine is not created until you call [`evolve`](Self::evolve) to transform
/// this into an initialized [`MultiUseSandbox`].
pub struct UninitializedSandbox {
    /// Registered host functions
    pub(crate) host_funcs: Arc<Mutex<FunctionRegistry>>,
    /// The memory manager for the sandbox.
    pub(crate) mgr: SandboxMemoryManager<ExclusiveSharedMemory>,
    pub(crate) max_guest_log_level: Option<LevelFilter>,
    pub(crate) config: SandboxConfiguration,
    #[cfg(any(crashdump, gdb))]
    pub(crate) rt_cfg: SandboxRuntimeConfig,
    pub(crate) load_info: crate::mem::exe::LoadInfo,
    // This is needed to convey the stack pointer between the snapshot
    // and the HyperlightVm creation
    pub(crate) stack_top_gva: u64,
}

impl Debug for UninitializedSandbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UninitializedSandbox")
            .field("memory_layout", &self.mgr.layout)
            .finish()
    }
}

/// A `GuestBinary` is either a buffer or the file path to some data (e.g., a guest binary).
#[derive(Debug)]
pub enum GuestBinary<'a> {
    /// A buffer containing the GuestBinary
    Buffer(&'a [u8]),
    /// A path to the GuestBinary
    FilePath(String),
}
impl<'a> GuestBinary<'a> {
    /// If the guest binary is identified by a file, canonicalise the path
    ///
    /// For [`GuestBinary::FilePath`], this resolves the path to its canonical
    /// form. For [`GuestBinary::Buffer`], this method is a no-op.
    /// TODO: Maybe we should make the GuestEnvironment or
    ///       GuestBinary constructors crate-private and turn this
    ///       into an invariant on one of those types.
    pub fn canonicalize(&mut self) -> Result<()> {
        if let GuestBinary::FilePath(p) = self {
            let canon = Path::new(&p)
                .canonicalize()
                .map_err(|e| new_error!("GuestBinary not found: '{}': {}", p, e))?
                .into_os_string()
                .into_string()
                .map_err(|e| new_error!("Error converting OsString to String: {:?}", e))?;
            *self = GuestBinary::FilePath(canon)
        }
        Ok(())
    }
}

/// A `GuestBlob` containing data and the permissions for its use.
#[derive(Debug)]
pub struct GuestBlob<'a> {
    /// The data contained in the blob.
    pub data: &'a [u8],
    /// The permissions for the blob in memory.
    /// By default, it's READ
    pub permissions: MemoryRegionFlags,
}

impl<'a> From<&'a [u8]> for GuestBlob<'a> {
    fn from(data: &'a [u8]) -> Self {
        GuestBlob {
            data,
            permissions: DEFAULT_GUEST_BLOB_MEM_FLAGS,
        }
    }
}

/// Container for a guest binary and optional initialization data.
///
/// This struct combines a guest binary (either from a file or memory buffer) with
/// optional data that will be available to the guest during execution.
#[derive(Debug)]
pub struct GuestEnvironment<'a, 'b> {
    /// The guest binary, which can be a file path or a buffer.
    pub guest_binary: GuestBinary<'a>,
    /// An optional guest blob, which can be used to provide additional data to the guest.
    pub init_data: Option<GuestBlob<'b>>,
}

impl<'a, 'b> GuestEnvironment<'a, 'b> {
    /// Creates a new `GuestEnvironment` with the given guest binary and an optional guest blob.
    pub fn new(guest_binary: GuestBinary<'a>, init_data: Option<&'b [u8]>) -> Self {
        GuestEnvironment {
            guest_binary,
            init_data: init_data.map(GuestBlob::from),
        }
    }
}

impl<'a> From<GuestBinary<'a>> for GuestEnvironment<'a, '_> {
    fn from(guest_binary: GuestBinary<'a>) -> Self {
        GuestEnvironment {
            guest_binary,
            init_data: None,
        }
    }
}

impl UninitializedSandbox {
    // Creates a new uninitialized sandbox from a pre-built snapshot.
    // Note that since memory configuration is part of the snapshot the only configuration
    // that can be changed (from the original snapshot) is the configuration defines the behaviour of
    // `InterruptHandler` on Linux.
    //
    // This is ok for now as this is not a public function
    fn from_snapshot(
        snapshot: Arc<Snapshot>,
        cfg: Option<SandboxConfiguration>,
        #[cfg(crashdump)] binary_path: Option<String>,
    ) -> Result<Self> {
        #[cfg(feature = "build-metadata")]
        log_build_details();

        // hyperlight is only supported on Windows 11 and Windows Server 2022 and later
        #[cfg(target_os = "windows")]
        check_windows_version()?;

        let sandbox_cfg = cfg.unwrap_or_default();

        #[cfg(any(crashdump, gdb))]
        let rt_cfg = {
            #[cfg(crashdump)]
            let guest_core_dump = sandbox_cfg.get_guest_core_dump();

            #[cfg(gdb)]
            let debug_info = sandbox_cfg.get_guest_debug_info();

            SandboxRuntimeConfig {
                #[cfg(crashdump)]
                binary_path,
                #[cfg(gdb)]
                debug_info,
                #[cfg(crashdump)]
                guest_core_dump,
            }
        };

        let mut mem_mgr_wrapper =
            SandboxMemoryManager::<ExclusiveSharedMemory>::from_snapshot(snapshot.as_ref())?;

        mem_mgr_wrapper.write_memory_layout()?;

        let host_funcs = Arc::new(Mutex::new(FunctionRegistry::default()));

        let mut sandbox = Self {
            host_funcs,
            mgr: mem_mgr_wrapper,
            max_guest_log_level: None,
            config: sandbox_cfg,
            #[cfg(any(crashdump, gdb))]
            rt_cfg,
            load_info: snapshot.load_info(),
            stack_top_gva: snapshot.stack_top_gva(),
        };

        // If we were passed a writer for host print register it otherwise use the default.
        sandbox.register_print(default_writer_func)?;

        crate::debug!("Sandbox created:  {:#?}", sandbox);

        Ok(sandbox)
    }

    /// Creates a new uninitialized sandbox for the given guest environment.
    ///
    /// The guest binary can be provided as either a file path or memory buffer.
    /// An optional configuration can customize memory sizes and sandbox settings.
    /// After creation, register host functions using [`register`](Self::register)
    /// before calling [`evolve`](Self::evolve) to complete initialization and create the VM.
    #[instrument(
        err(Debug),
        skip(env),
        parent = Span::current()
    )]
    pub fn new<'a, 'b>(
        env: impl Into<GuestEnvironment<'a, 'b>>,
        cfg: Option<SandboxConfiguration>,
    ) -> Result<Self> {
        let cfg = cfg.unwrap_or_default();
        let env = env.into();
        #[cfg(crashdump)]
        let binary_path = match &env.guest_binary {
            GuestBinary::FilePath(path) => Some(path.clone()),
            GuestBinary::Buffer(_) => None,
        };
        let snapshot = Snapshot::from_env(env, cfg)?;
        Self::from_snapshot(
            Arc::new(snapshot),
            Some(cfg),
            #[cfg(crashdump)]
            binary_path,
        )
    }

    /// Creates and initializes the virtual machine, transforming this into a ready-to-use sandbox.
    ///
    /// This method consumes the `UninitializedSandbox` and performs the final initialization
    /// steps to create the underlying virtual machine. Once evolved, the resulting
    /// [`MultiUseSandbox`] can execute guest code and handle function calls.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    pub fn evolve(self) -> Result<MultiUseSandbox> {
        evolve_impl_multi_use(self)
    }

    /// Sets the maximum log level for guest code execution.
    ///
    /// If not set, the log level is determined by the `RUST_LOG` environment variable,
    /// defaulting to [`LevelFilter::Error`] if unset.
    pub fn set_max_guest_log_level(&mut self, log_level: LevelFilter) {
        self.max_guest_log_level = Some(log_level);
    }

    /// Registers a host function that the guest can call.
    pub fn register<Args: ParameterTuple, Output: SupportedReturnType>(
        &mut self,
        name: impl AsRef<str>,
        host_func: impl Into<HostFunction<Output, Args>>,
    ) -> Result<()> {
        register_host_function(host_func, self, name.as_ref())
    }

    /// Registers the special "HostPrint" function for guest printing.
    ///
    /// This overrides the default behavior of writing to stdout.
    /// The function expects the signature `FnMut(String) -> i32`
    /// and will be called when the guest wants to print output.
    pub fn register_print(
        &mut self,
        print_func: impl Into<HostFunction<i32, (String,)>>,
    ) -> Result<()> {
        self.register("HostPrint", print_func)
    }
}
// Check to see if the current version of Windows is supported
// Hyperlight is only supported on Windows 11 and Windows Server 2022 and later
#[cfg(target_os = "windows")]
fn check_windows_version() -> Result<()> {
    use windows_version::{OsVersion, is_server};
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::mpsc::channel;
    use std::{fs, thread};

    use crossbeam_queue::ArrayQueue;
    use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterValue, ReturnValue};
    use hyperlight_testing::simple_guest_as_string;

    use crate::sandbox::SandboxConfiguration;
    use crate::sandbox::uninitialized::{GuestBinary, GuestEnvironment};
    use crate::{MultiUseSandbox, Result, UninitializedSandbox, new_error};

    #[test]
    fn test_load_extra_blob() {
        let binary_path = simple_guest_as_string().unwrap();
        let buffer = [0xde, 0xad, 0xbe, 0xef];
        let guest_env =
            GuestEnvironment::new(GuestBinary::FilePath(binary_path.clone()), Some(&buffer));

        let uninitialized_sandbox = UninitializedSandbox::new(guest_env, None).unwrap();
        let mut sandbox: MultiUseSandbox = uninitialized_sandbox.evolve().unwrap();

        let res = sandbox
            .call::<Vec<u8>>("ReadFromUserMemory", (4u64, buffer.to_vec()))
            .expect("Failed to call ReadFromUserMemory");

        assert_eq!(res, buffer.to_vec());
    }

    #[test]
    fn test_new_sandbox() {
        // Guest Binary exists at path

        let binary_path = simple_guest_as_string().unwrap();
        let sandbox = UninitializedSandbox::new(GuestBinary::FilePath(binary_path.clone()), None);
        assert!(sandbox.is_ok());

        // Guest Binary does not exist at path

        let mut binary_path_does_not_exist = binary_path.clone();
        binary_path_does_not_exist.push_str(".nonexistent");
        let uninitialized_sandbox =
            UninitializedSandbox::new(GuestBinary::FilePath(binary_path_does_not_exist), None);
        assert!(uninitialized_sandbox.is_err());

        // Non default memory configuration
        let cfg = {
            let mut cfg = SandboxConfiguration::default();
            cfg.set_input_data_size(0x1000);
            cfg.set_output_data_size(0x1000);
            cfg.set_heap_size(0x1000);
            Some(cfg)
        };

        let uninitialized_sandbox =
            UninitializedSandbox::new(GuestBinary::FilePath(binary_path.clone()), cfg);
        assert!(uninitialized_sandbox.is_ok());

        let uninitialized_sandbox =
            UninitializedSandbox::new(GuestBinary::FilePath(binary_path), None).unwrap();

        // Get a Sandbox from an uninitialized sandbox without a call back function

        let _sandbox: MultiUseSandbox = uninitialized_sandbox.evolve().unwrap();

        // Test with a valid guest binary buffer

        let binary_path = simple_guest_as_string().unwrap();
        let sandbox =
            UninitializedSandbox::new(GuestBinary::Buffer(&fs::read(binary_path).unwrap()), None);
        assert!(sandbox.is_ok());

        // Test with a invalid guest binary buffer

        let binary_path = simple_guest_as_string().unwrap();
        let mut bytes = fs::read(binary_path).unwrap();
        let _ = bytes.split_off(100);
        let sandbox = UninitializedSandbox::new(GuestBinary::Buffer(&bytes), None);
        assert!(sandbox.is_err());
    }

    #[test]
    fn test_host_functions() {
        let uninitialized_sandbox = || {
            UninitializedSandbox::new(
                GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
                None,
            )
            .unwrap()
        };

        // simple register + call
        {
            let mut usbox = uninitialized_sandbox();

            usbox.register("test0", |arg: i32| Ok(arg + 1)).unwrap();

            let sandbox: Result<MultiUseSandbox> = usbox.evolve();
            assert!(sandbox.is_ok());
            let sandbox = sandbox.unwrap();

            let host_funcs = sandbox
                .host_funcs
                .try_lock()
                .map_err(|_| new_error!("Error locking"));

            assert!(host_funcs.is_ok());

            let res = host_funcs
                .unwrap()
                .call_host_function("test0", vec![ParameterValue::Int(1)])
                .unwrap();

            assert_eq!(res, ReturnValue::Int(2));
        }

        // multiple parameters register + call
        {
            let mut usbox = uninitialized_sandbox();

            usbox.register("test1", |a: i32, b: i32| Ok(a + b)).unwrap();

            let sandbox: Result<MultiUseSandbox> = usbox.evolve();
            assert!(sandbox.is_ok());
            let sandbox = sandbox.unwrap();

            let host_funcs = sandbox
                .host_funcs
                .try_lock()
                .map_err(|_| new_error!("Error locking"));

            assert!(host_funcs.is_ok());

            let res = host_funcs
                .unwrap()
                .call_host_function(
                    "test1",
                    vec![ParameterValue::Int(1), ParameterValue::Int(2)],
                )
                .unwrap();

            assert_eq!(res, ReturnValue::Int(3));
        }

        // incorrect arguments register + call
        {
            let mut usbox = uninitialized_sandbox();

            usbox
                .register("test2", |msg: String| {
                    println!("test2 called: {}", msg);
                    Ok(())
                })
                .unwrap();

            let sandbox: Result<MultiUseSandbox> = usbox.evolve();
            assert!(sandbox.is_ok());
            let sandbox = sandbox.unwrap();

            let host_funcs = sandbox
                .host_funcs
                .try_lock()
                .map_err(|_| new_error!("Error locking"));

            assert!(host_funcs.is_ok());

            let res = host_funcs.unwrap().call_host_function("test2", vec![]);
            assert!(res.is_err());
        }

        // calling a function that doesn't exist
        {
            let usbox = uninitialized_sandbox();
            let sandbox: Result<MultiUseSandbox> = usbox.evolve();
            assert!(sandbox.is_ok());
            let sandbox = sandbox.unwrap();

            let host_funcs = sandbox
                .host_funcs
                .try_lock()
                .map_err(|_| new_error!("Error locking"));

            assert!(host_funcs.is_ok());

            let res = host_funcs.unwrap().call_host_function("test4", vec![]);
            assert!(res.is_err());
        }
    }

    #[test]
    fn test_host_print() {
        // writer as a FnMut closure mutating a captured variable and then trying to access the captured variable
        // after the Sandbox instance has been dropped
        // this example is fairly contrived but we should still support such an approach.

        let (tx, rx) = channel();

        let writer = move |msg| {
            let _ = tx.send(msg);
            Ok(0)
        };

        let mut sandbox = UninitializedSandbox::new(
            GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
            None,
        )
        .expect("Failed to create sandbox");

        sandbox
            .register_print(writer)
            .expect("Failed to register host print function");

        let host_funcs = sandbox
            .host_funcs
            .try_lock()
            .map_err(|_| new_error!("Error locking"));

        assert!(host_funcs.is_ok());

        host_funcs.unwrap().host_print("test".to_string()).unwrap();

        drop(sandbox);

        let received_msgs: Vec<_> = rx.into_iter().collect();
        assert_eq!(received_msgs, ["test"]);

        // There may be cases where a mutable reference to the captured variable is not required to be used outside the closure
        // e.g. if the function is writing to a file or a socket etc.

        // writer as a FnMut closure mutating a captured variable but not trying to access the captured variable

        // This seems more realistic as the client is creating a file to be written to in the closure
        // and then accessing the file a different handle.
        // The problem is that captured_file still needs static lifetime so even though we can access the data through the second file handle
        // this still does not work as the captured_file is dropped at the end of the function

        // TODO: Currently, we block any writes that are not to
        // the stdout/stderr file handles, so this code is commented
        // out until we can register writer functions like any other
        // host functions with their own set of extra allowed syscalls.
        // In particular, this code should be brought back once we have addressed the issue

        // let captured_file = Arc::new(Mutex::new(NamedTempFile::new().unwrap()));
        // let capture_file_clone = captured_file.clone();
        //
        // let capture_file_lock = captured_file
        //     .try_lock()
        //     .map_err(|_| new_error!("Error locking"))
        //     .unwrap();
        // let mut file = capture_file_lock.reopen().unwrap();
        // drop(capture_file_lock);
        //
        // let writer = move |msg: String| -> Result<i32> {
        //     let mut captured_file = capture_file_clone
        //         .try_lock()
        //         .map_err(|_| new_error!("Error locking"))
        //         .unwrap();
        //     captured_file.write_all(msg.as_bytes()).unwrap();
        //     Ok(0)
        // };
        //
        // let writer_func = Arc::new(Mutex::new(writer));
        //
        // let sandbox = UninitializedSandbox::new(
        //     GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
        //     None,
        //     None,
        //     Some(&writer_func),
        // )
        // .expect("Failed to create sandbox");
        //
        // let host_funcs = sandbox
        //     .host_funcs
        //     .try_lock()
        //     .map_err(|_| new_error!("Error locking"));
        //
        // assert!(host_funcs.is_ok());
        //
        // host_funcs.unwrap().host_print("test2".to_string()).unwrap();
        //
        // let mut buffer = String::new();
        // file.read_to_string(&mut buffer).unwrap();
        // assert_eq!(buffer, "test2");

        // writer as a function

        fn fn_writer(msg: String) -> Result<i32> {
            assert_eq!(msg, "test2");
            Ok(0)
        }

        let mut sandbox = UninitializedSandbox::new(
            GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
            None,
        )
        .expect("Failed to create sandbox");

        sandbox
            .register_print(fn_writer)
            .expect("Failed to register host print function");

        let host_funcs = sandbox
            .host_funcs
            .try_lock()
            .map_err(|_| new_error!("Error locking"));

        assert!(host_funcs.is_ok());

        host_funcs.unwrap().host_print("test2".to_string()).unwrap();

        // writer as a method

        let mut test_host_print = TestHostPrint::new();

        // create a closure over the struct method

        let writer_closure = move |s| test_host_print.write(s);

        let mut sandbox = UninitializedSandbox::new(
            GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
            None,
        )
        .expect("Failed to create sandbox");

        sandbox
            .register_print(writer_closure)
            .expect("Failed to register host print function");

        let host_funcs = sandbox
            .host_funcs
            .try_lock()
            .map_err(|_| new_error!("Error locking"));

        assert!(host_funcs.is_ok());

        host_funcs.unwrap().host_print("test3".to_string()).unwrap();
    }

    struct TestHostPrint {}

    impl TestHostPrint {
        fn new() -> Self {
            TestHostPrint {}
        }

        fn write(&mut self, msg: String) -> Result<i32> {
            assert_eq!(msg, "test3");
            Ok(0)
        }
    }

    #[test]
    fn check_create_and_use_sandbox_on_different_threads() {
        let unintializedsandbox_queue = Arc::new(ArrayQueue::<UninitializedSandbox>::new(10));
        let sandbox_queue = Arc::new(ArrayQueue::<MultiUseSandbox>::new(10));

        for i in 0..10 {
            let simple_guest_path = simple_guest_as_string().expect("Guest Binary Missing");
            let unintializedsandbox = {
                let err_string = format!("failed to create UninitializedSandbox {i}");
                let err_str = err_string.as_str();
                UninitializedSandbox::new(GuestBinary::FilePath(simple_guest_path), None)
                    .expect(err_str)
            };

            {
                let err_string = format!("Failed to push UninitializedSandbox {i}");
                let err_str = err_string.as_str();

                unintializedsandbox_queue
                    .push(unintializedsandbox)
                    .expect(err_str);
            }
        }

        let thread_handles = (0..10)
            .map(|i| {
                let uq = unintializedsandbox_queue.clone();
                let sq = sandbox_queue.clone();
                thread::spawn(move || {
                    let uninitialized_sandbox = uq.pop().unwrap_or_else(|| {
                        panic!("Failed to pop UninitializedSandbox thread {}", i)
                    });

                    let host_funcs = uninitialized_sandbox
                        .host_funcs
                        .try_lock()
                        .map_err(|_| new_error!("Error locking"));

                    assert!(host_funcs.is_ok());

                    host_funcs
                        .unwrap()
                        .host_print(format!("Print from UninitializedSandbox on Thread {}\n", i))
                        .unwrap();

                    let sandbox = uninitialized_sandbox.evolve().unwrap_or_else(|_| {
                        panic!("Failed to initialize UninitializedSandbox thread {}", i)
                    });

                    sq.push(sandbox).unwrap_or_else(|_| {
                        panic!("Failed to push UninitializedSandbox thread {}", i)
                    })
                })
            })
            .collect::<Vec<_>>();

        for handle in thread_handles {
            handle.join().unwrap();
        }

        let thread_handles = (0..10)
            .map(|i| {
                let sq = sandbox_queue.clone();
                thread::spawn(move || {
                    let sandbox = sq
                        .pop()
                        .unwrap_or_else(|| panic!("Failed to pop Sandbox thread {}", i));

                    let host_funcs = sandbox
                        .host_funcs
                        .try_lock()
                        .map_err(|_| new_error!("Error locking"));

                    assert!(host_funcs.is_ok());

                    host_funcs
                        .unwrap()
                        .host_print(format!("Print from Sandbox on Thread {}\n", i))
                        .unwrap();
                })
            })
            .collect::<Vec<_>>();

        for handle in thread_handles {
            handle.join().unwrap();
        }
    }

    #[test]
    // Tests that trace data are emitted when a trace subscriber is set
    // this test is ignored because it is incompatible with other tests , specifically those which require a logger for tracing
    // marking  this test as ignored means that running `cargo test` will not run this test but will allow a developer who runs that command
    // from their workstation to be successful without needed to know about test interdependencies
    // this test will be run explicitly as a part of the CI pipeline
    #[ignore]
    #[cfg(feature = "build-metadata")]
    fn test_trace_trace() {
        use hyperlight_testing::logger::Logger as TestLogger;
        use hyperlight_testing::tracing_subscriber::TracingSubscriber as TestSubscriber;
        use serde_json::{Map, Value};
        use tracing::Level as tracing_level;
        use tracing_core::Subscriber;
        use tracing_core::callsite::rebuild_interest_cache;
        use uuid::Uuid;

        use crate::testing::log_values::build_metadata_testing::try_to_strings;
        use crate::testing::log_values::test_value_as_str;

        TestLogger::initialize_log_tracer();
        rebuild_interest_cache();
        let subscriber = TestSubscriber::new(tracing_level::TRACE);
        tracing::subscriber::with_default(subscriber.clone(), || {
            let correlation_id = Uuid::new_v4().as_hyphenated().to_string();
            let span = tracing::error_span!("test_trace_logs", correlation_id).entered();

            // We should be in span 1

            let current_span = subscriber.current_span();
            assert!(current_span.is_known(), "Current span is unknown");
            let current_span_metadata = current_span.into_inner().unwrap();
            assert_eq!(
                current_span_metadata.0.into_u64(),
                1,
                "Current span is not span 1"
            );
            assert_eq!(current_span_metadata.1.name(), "test_trace_logs");

            // Get the span data and check the correlation id

            let span_data = subscriber.get_span(1);
            let span_attributes: &Map<String, Value> = span_data
                .get("span")
                .unwrap()
                .get("attributes")
                .unwrap()
                .as_object()
                .unwrap();

            test_value_as_str(span_attributes, "correlation_id", correlation_id.as_str());

            let mut binary_path = simple_guest_as_string().unwrap();
            binary_path.push_str("does_not_exist");

            let sbox = UninitializedSandbox::new(GuestBinary::FilePath(binary_path), None);
            assert!(sbox.is_err());

            // Now we should still be in span 1 but span 2 should be created (we created entered and exited span 2 when we called UninitializedSandbox::new)

            let current_span = subscriber.current_span();
            assert!(current_span.is_known(), "Current span is unknown");
            let current_span_metadata = current_span.into_inner().unwrap();
            assert_eq!(
                current_span_metadata.0.into_u64(),
                1,
                "Current span is not span 1"
            );

            let span_metadata = subscriber.get_span_metadata(2);
            assert_eq!(span_metadata.name(), "new");

            // There should be one event for the error that the binary path does not exist plus 14 info events for the logging of the crate info

            let events = subscriber.get_events();
            assert_eq!(events.len(), 1);

            let mut count_matching_events = 0;

            for json_value in events {
                let event_values = json_value.as_object().unwrap().get("event").unwrap();
                let metadata_values_map =
                    event_values.get("metadata").unwrap().as_object().unwrap();
                let event_values_map = event_values.as_object().unwrap();

                let expected_error_start = "Error(\"GuestBinary not found:";

                let err_vals_res = try_to_strings([
                    (metadata_values_map, "level"),
                    (event_values_map, "error"),
                    (metadata_values_map, "module_path"),
                    (metadata_values_map, "target"),
                ]);
                if let Ok(err_vals) = err_vals_res
                    && err_vals[0] == "ERROR"
                    && err_vals[1].starts_with(expected_error_start)
                    && err_vals[2] == "hyperlight_host::sandbox::uninitialized"
                    && err_vals[3] == "hyperlight_host::sandbox::uninitialized"
                {
                    count_matching_events += 1;
                }
            }
            assert!(
                count_matching_events == 1,
                "Unexpected number of matching events {}",
                count_matching_events
            );
            span.exit();
            subscriber.clear();
        });
    }

    #[test]
    #[ignore]
    // Tests that traces are emitted as log records when there is no trace
    // subscriber configured.
    #[cfg(feature = "build-metadata")]
    fn test_log_trace() {
        use std::path::PathBuf;

        use hyperlight_testing::logger::{LOGGER as TEST_LOGGER, Logger as TestLogger};
        use log::Level;
        use tracing_core::callsite::rebuild_interest_cache;

        {
            TestLogger::initialize_test_logger();
            TEST_LOGGER.set_max_level(log::LevelFilter::Trace);

            // This makes sure that the metadata interest cache is rebuilt so that
            // the log records are emitted for the trace records

            rebuild_interest_cache();

            let mut invalid_binary_path = simple_guest_as_string().unwrap();
            invalid_binary_path.push_str("does_not_exist");

            let sbox = UninitializedSandbox::new(GuestBinary::FilePath(invalid_binary_path), None);
            assert!(sbox.is_err());

            // When tracing is creating log records it will create a log
            // record for the creation of the span (from the instrument
            // attribute), and will then create a log record for the entry to
            // and exit from the span.
            //
            // It also creates a log record for the span being dropped.
            //
            // In addition there are 14 info log records created for build information
            //
            // So we expect 19 log records for this test, four for the span and
            // then one for the error as the file that we are attempting to
            // load into the sandbox does not exist, plus the 14 info log records

            let num_calls = TEST_LOGGER.num_log_calls();
            assert_eq!(13, num_calls);

            // Log record 1

            let logcall = TEST_LOGGER.get_log_call(0).unwrap();
            assert_eq!(Level::Info, logcall.level);

            assert!(logcall.args.starts_with("new; cfg"));
            assert_eq!("hyperlight_host::sandbox::uninitialized", logcall.target);

            // Log record 2

            let logcall = TEST_LOGGER.get_log_call(1).unwrap();
            assert_eq!(Level::Trace, logcall.level);
            assert_eq!(logcall.args, "-> new;");
            assert_eq!("tracing::span::active", logcall.target);

            // Log record 17

            let logcall = TEST_LOGGER.get_log_call(10).unwrap();
            assert_eq!(Level::Error, logcall.level);
            assert!(
                logcall
                    .args
                    .starts_with("error=Error(\"GuestBinary not found:")
            );
            assert_eq!("hyperlight_host::sandbox::uninitialized", logcall.target);

            // Log record 18

            let logcall = TEST_LOGGER.get_log_call(11).unwrap();
            assert_eq!(Level::Trace, logcall.level);
            assert_eq!(logcall.args, "<- new;");
            assert_eq!("tracing::span::active", logcall.target);

            // Log record 19

            let logcall = TEST_LOGGER.get_log_call(12).unwrap();
            assert_eq!(Level::Trace, logcall.level);
            assert_eq!(logcall.args, "-- new;");
            assert_eq!("tracing::span", logcall.target);
        }
        {
            // test to ensure an invalid binary logs & traces properly
            TEST_LOGGER.clear_log_calls();
            TEST_LOGGER.set_max_level(log::LevelFilter::Info);

            let mut valid_binary_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            valid_binary_path.push("src");
            valid_binary_path.push("sandbox");
            valid_binary_path.push("initialized.rs");

            let sbox = UninitializedSandbox::new(
                GuestBinary::FilePath(valid_binary_path.into_os_string().into_string().unwrap()),
                None,
            );
            assert!(sbox.is_err());

            // There should be 2 calls this time when we change to the log
            // LevelFilter to Info.
            let num_calls = TEST_LOGGER.num_log_calls();
            assert_eq!(2, num_calls);

            // Log record 1

            let logcall = TEST_LOGGER.get_log_call(0).unwrap();
            assert_eq!(Level::Info, logcall.level);

            assert!(logcall.args.starts_with("new; cfg"));
            assert_eq!("hyperlight_host::sandbox::uninitialized", logcall.target);

            // Log record 2

            let logcall = TEST_LOGGER.get_log_call(1).unwrap();
            assert_eq!(Level::Error, logcall.level);
            assert!(
                logcall
                    .args
                    .starts_with("error=Error(\"GuestBinary not found:")
            );
            assert_eq!("hyperlight_host::sandbox::uninitialized", logcall.target);
        }
        {
            TEST_LOGGER.clear_log_calls();
            TEST_LOGGER.set_max_level(log::LevelFilter::Error);

            let sbox = {
                let res = UninitializedSandbox::new(
                    GuestBinary::FilePath(simple_guest_as_string().unwrap()),
                    None,
                );
                res.unwrap()
            };
            let _: Result<MultiUseSandbox> = sbox.evolve();

            let num_calls = TEST_LOGGER.num_log_calls();

            assert_eq!(0, num_calls);
        }
    }

    #[test]
    fn test_invalid_path() {
        let invalid_path = "some/path/that/does/not/exist";
        let sbox = UninitializedSandbox::new(GuestBinary::FilePath(invalid_path.to_string()), None);
        println!("{:?}", sbox);
        #[cfg(target_os = "windows")]
        assert!(
            matches!(sbox, Err(e) if e.to_string().contains("GuestBinary not found: 'some/path/that/does/not/exist': The system cannot find the path specified. (os error 3)"))
        );
        #[cfg(target_os = "linux")]
        assert!(
            matches!(sbox, Err(e) if e.to_string().contains("GuestBinary not found: 'some/path/that/does/not/exist': No such file or directory (os error 2)"))
        );
    }

    #[test]
    fn test_from_snapshot_various_configurations() {
        use crate::sandbox::snapshot::Snapshot;

        let binary_path = simple_guest_as_string().unwrap();

        // Test 1: Create snapshot with default config, create multiple sandboxes from it
        {
            let env = GuestEnvironment::new(GuestBinary::FilePath(binary_path.clone()), None);

            let snapshot = Arc::new(
                Snapshot::from_env(env, Default::default())
                    .expect("Failed to create snapshot with default config"),
            );

            // Create first sandbox from snapshot
            let sandbox1 = UninitializedSandbox::from_snapshot(
                snapshot.clone(),
                None,
                #[cfg(crashdump)]
                Some(binary_path.clone()),
            )
            .expect("Failed to create first sandbox from snapshot");

            // Create second sandbox from same snapshot
            let sandbox2 = UninitializedSandbox::from_snapshot(
                snapshot.clone(),
                None,
                #[cfg(crashdump)]
                Some(binary_path.clone()),
            )
            .expect("Failed to create second sandbox from snapshot");

            // Both should be able to evolve independently
            let _evolved1: MultiUseSandbox = sandbox1.evolve().expect("Failed to evolve sandbox1");
            let _evolved2: MultiUseSandbox = sandbox2.evolve().expect("Failed to evolve sandbox2");
        }

        // Test 2: Create snapshot with custom heap size
        {
            let mut cfg = SandboxConfiguration::default();
            cfg.set_heap_size(16 * 1024 * 1024); // 16MB heap

            let env = GuestEnvironment::new(GuestBinary::FilePath(binary_path.clone()), None);

            let snapshot = Arc::new(
                Snapshot::from_env(env, cfg)
                    .expect("Failed to create snapshot with custom heap size"),
            );

            let sandbox = UninitializedSandbox::from_snapshot(
                snapshot,
                None,
                #[cfg(crashdump)]
                Some(binary_path.clone()),
            )
            .expect("Failed to create sandbox from snapshot with custom heap");

            let _evolved: MultiUseSandbox = sandbox.evolve().expect("Failed to evolve sandbox");
        }

        // Test 3: Create snapshot with custom scratch size
        {
            let mut cfg = SandboxConfiguration::default();
            cfg.set_scratch_size(128 * 1024); // 128KB scratch

            let env = GuestEnvironment::new(GuestBinary::FilePath(binary_path.clone()), None);

            let snapshot = Arc::new(
                Snapshot::from_env(env, cfg)
                    .expect("Failed to create snapshot with custom stack size"),
            );

            let sandbox = UninitializedSandbox::from_snapshot(
                snapshot,
                None,
                #[cfg(crashdump)]
                Some(binary_path.clone()),
            )
            .expect("Failed to create sandbox from snapshot with custom stack");

            let _evolved: MultiUseSandbox = sandbox.evolve().expect("Failed to evolve sandbox");
        }

        // Test 4: Create snapshot with custom input/output buffer sizes
        {
            let mut cfg = SandboxConfiguration::default();
            cfg.set_input_data_size(64 * 1024); // 64KB input
            cfg.set_output_data_size(64 * 1024); // 64KB output

            let env = GuestEnvironment::new(GuestBinary::FilePath(binary_path.clone()), None);

            let snapshot = Arc::new(
                Snapshot::from_env(env, cfg)
                    .expect("Failed to create snapshot with custom buffer sizes"),
            );

            let sandbox = UninitializedSandbox::from_snapshot(
                snapshot,
                None,
                #[cfg(crashdump)]
                Some(binary_path.clone()),
            )
            .expect("Failed to create sandbox from snapshot with custom buffers");

            let _evolved: MultiUseSandbox = sandbox.evolve().expect("Failed to evolve sandbox");
        }

        // Test 5: Create snapshot with all custom settings
        {
            let mut cfg = SandboxConfiguration::default();
            cfg.set_heap_size(32 * 1024 * 1024); // 32MB heap
            cfg.set_scratch_size(256 * 1024); // 256KB scratch
            cfg.set_input_data_size(128 * 1024); // 128KB input
            cfg.set_output_data_size(128 * 1024); // 128KB output

            let env = GuestEnvironment::new(GuestBinary::FilePath(binary_path.clone()), None);

            let snapshot = Arc::new(
                Snapshot::from_env(env, cfg)
                    .expect("Failed to create snapshot with all custom settings"),
            );

            // Create multiple sandboxes from the same snapshot
            let sandbox1 = UninitializedSandbox::from_snapshot(
                snapshot.clone(),
                None,
                #[cfg(crashdump)]
                Some(binary_path.clone()),
            )
            .expect("Failed to create sandbox1 from fully customized snapshot");
            let sandbox2 = UninitializedSandbox::from_snapshot(
                snapshot.clone(),
                None,
                #[cfg(crashdump)]
                Some(binary_path.clone()),
            )
            .expect("Failed to create sandbox2 from fully customized snapshot");
            let sandbox3 = UninitializedSandbox::from_snapshot(
                snapshot.clone(),
                None,
                #[cfg(crashdump)]
                Some(binary_path.clone()),
            )
            .expect("Failed to create sandbox3 from fully customized snapshot");

            let _evolved1: MultiUseSandbox = sandbox1.evolve().expect("Failed to evolve sandbox1");
            let _evolved2: MultiUseSandbox = sandbox2.evolve().expect("Failed to evolve sandbox2");
            let _evolved3: MultiUseSandbox = sandbox3.evolve().expect("Failed to evolve sandbox3");
        }

        // Test 6: Create snapshot from binary buffer instead of file path
        {
            let binary_bytes = fs::read(&binary_path).expect("Failed to read binary file");

            let snapshot = Arc::new(
                Snapshot::from_env(GuestBinary::Buffer(&binary_bytes), Default::default())
                    .expect("Failed to create snapshot from buffer"),
            );

            let sandbox = UninitializedSandbox::from_snapshot(
                snapshot,
                None,
                #[cfg(crashdump)]
                None,
            )
            .expect("Failed to create sandbox from buffer-based snapshot");

            let _evolved: MultiUseSandbox = sandbox.evolve().expect("Failed to evolve sandbox");
        }

        // Test 7: Register host functions on sandboxes created from snapshot
        {
            let env = GuestEnvironment::new(GuestBinary::FilePath(binary_path.clone()), None);

            let snapshot = Arc::new(
                Snapshot::from_env(env, Default::default()).expect("Failed to create snapshot"),
            );

            let mut sandbox = UninitializedSandbox::from_snapshot(
                snapshot,
                None,
                #[cfg(crashdump)]
                Some(binary_path.clone()),
            )
            .expect("Failed to create sandbox from snapshot");

            // Register a custom host function
            sandbox
                .register("CustomAdd", |a: i32, b: i32| Ok(a + b))
                .expect("Failed to register custom function");

            let evolved: MultiUseSandbox = sandbox.evolve().expect("Failed to evolve sandbox");

            // Verify the host function was registered
            let host_funcs = evolved
                .host_funcs
                .try_lock()
                .expect("Failed to lock host funcs");

            let result = host_funcs
                .call_host_function(
                    "CustomAdd",
                    vec![ParameterValue::Int(10), ParameterValue::Int(20)],
                )
                .expect("Failed to call CustomAdd");

            assert_eq!(result, ReturnValue::Int(30));
        }

        // Test 8: Create snapshot with init data (guest blob)
        {
            let init_data = [0xCA, 0xFE, 0xBA, 0xBE];
            let guest_env =
                GuestEnvironment::new(GuestBinary::FilePath(binary_path.clone()), Some(&init_data));

            let snapshot = Arc::new(
                Snapshot::from_env(guest_env, Default::default())
                    .expect("Failed to create snapshot with init data"),
            );

            let sandbox = UninitializedSandbox::from_snapshot(
                snapshot,
                None,
                #[cfg(crashdump)]
                Some(binary_path.clone()),
            )
            .expect("Failed to create sandbox from snapshot with init data");

            let _evolved: MultiUseSandbox = sandbox.evolve().expect("Failed to evolve sandbox");
        }

        // Test 9: Create snapshot from existing sandbox
        {
            let env = GuestEnvironment::new(GuestBinary::FilePath(binary_path.clone()), None);
            let orig_snapshot = Arc::new(
                Snapshot::from_env(env, Default::default())
                    .expect("Failed to create snapshot with default config"),
            );
            let orig_sandbox = UninitializedSandbox::from_snapshot(
                orig_snapshot,
                None,
                #[cfg(crashdump)]
                Some(binary_path.clone()),
            )
            .expect("Failed to create orig_sandbox");
            let mut initialized_sandbox = orig_sandbox
                .evolve()
                .expect("Failed to evolve orig_sandbox");
            let new_snapshot = initialized_sandbox
                .snapshot()
                .expect("Failed to create new_snapshot");
            let new_sandbox = UninitializedSandbox::from_snapshot(
                new_snapshot,
                None,
                #[cfg(crashdump)]
                Some(binary_path.clone()),
            )
            .expect("Failed to create new_sandbox");
            let _evolved = new_sandbox.evolve().expect("Failed to evolve new_sandbox");
        }
    }
}
