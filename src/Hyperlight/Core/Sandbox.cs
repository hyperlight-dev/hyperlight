using System;
using System.Collections.Concurrent;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using Hyperlight.Core;
using Hyperlight.Hypervisors;
using Hyperlight.Native;

namespace Hyperlight
{

    [Flags]
    public enum SandboxRunOptions
    {
        None = 0,
        RunInProcess = 1,
        RecycleAfterRun = 2,
        RunFromGuestBinary = 4,
    }
    public class Sandbox : IDisposable, ISandboxRegistration
    {
        static readonly object peInfoLock = new();
        static readonly ConcurrentDictionary<string, PEInfo> guestPEInfo = new(StringComparer.InvariantCultureIgnoreCase);
        static bool IsWindows => RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
        static bool IsLinux => RuntimeInformation.IsOSPlatform(OSPlatform.Linux);
        public static bool IsSupportedPlatform => IsLinux || IsWindows;
        Hypervisor hyperVisor;
        GCHandle? gCHandle;
        readonly string guestBinaryPath;
        readonly SandboxMemoryManager sandboxMemoryManager;
        readonly bool initialised;
        readonly bool recycleAfterRun;
        readonly bool runFromProcessMemory;
        readonly bool runFromGuestBinary;
        bool didRunFromGuestBinary;
        const int IS_RUNNING_FROM_GUEST_BINARY = 1;
        // this is passed as a ref to several functions below,
        // therefore cannot be readonly
        static int isRunningFromGuestBinary;
        readonly StringWriter writer;
        readonly HyperlightGuestInterfaceGlue guestInterfaceGlue;
        private bool disposedValue; // To detect redundant calls
        HyperlightPEB hyperlightPEB;

        unsafe delegate* unmanaged<IntPtr, int> callEntryPoint;

        // Platform dependent delegate for callbacks from native code when native code is calling 'outb' functionality
        // On Linux, delegates passed from .NET core to native code expect arguments to be passed RDI, RSI, RDX, RCX.
        // On Windows, the expected order starts with RCX, RDX.  Our native code assumes this Windows calling convention
        // so 'port' is passed in RCX and 'value' is passed in RDX.  When run in Linux, we have an alternate callback
        // that will take RCX and RDX in the different positions and pass it to the HandleOutb method correctly

        delegate void CallOutb_Windows(ushort port, byte value);
        delegate void CallOutb_Linux(int unused1, int unused2, byte value, ushort port);
        delegate void CallDispatchFunction();

        // 0 No calls are executing
        // 1 Call guest is executing
        // 2 Dynamic Method is executing standalone
        int executingGuestCall;

        int countRunCalls;

        /// <summary>
        /// Returns the maximum number of partitions per process, on windows its the mximum number of processes that can be handled by the HyperVSurrogateProcessManager , on Linux its not fixed and dependent on resources.
        /// </summary>

        public static int MaxPartitionsPerProcess => IsWindows ? HyperVSurrogateProcessManager.NumberOfProcesses : -1;

        public Sandbox(SandboxMemoryConfiguration sandboxMemoryConfiguaration, string guestBinaryPath) : this(sandboxMemoryConfiguaration, guestBinaryPath, SandboxRunOptions.None, null, null)
        {
        }

        public Sandbox(SandboxMemoryConfiguration sandboxMemoryConfiguaration, string guestBinaryPath, Action<ISandboxRegistration> initFunction, StringWriter writer = null) : this(sandboxMemoryConfiguaration, guestBinaryPath, SandboxRunOptions.None, initFunction, writer)
        {
        }

        public Sandbox( string guestBinaryPath, Action<ISandboxRegistration> initFunction, StringWriter writer = null) : this(SandboxMemoryConfiguration.Default, guestBinaryPath, SandboxRunOptions.None, initFunction, writer)
        {
        }

        public Sandbox(string guestBinaryPath, Action<ISandboxRegistration> initFunction = null) : this(SandboxMemoryConfiguration.Default, guestBinaryPath, SandboxRunOptions.None, initFunction, null)
        {
        }

        public Sandbox(string guestBinaryPath, StringWriter writer = null) : this(SandboxMemoryConfiguration.Default, guestBinaryPath, SandboxRunOptions.None, null, writer)
        {
        }

        public Sandbox(SandboxMemoryConfiguration sandboxMemoryConfiguaration, string guestBinaryPath, StringWriter writer = null) : this(sandboxMemoryConfiguaration, guestBinaryPath, SandboxRunOptions.None, null, writer)
        {
        }

        public Sandbox(string guestBinaryPath, SandboxRunOptions runOptions, Action<ISandboxRegistration> initFunction) : this(SandboxMemoryConfiguration.Default, guestBinaryPath, runOptions, initFunction, null)
        {
        }

        public Sandbox(SandboxMemoryConfiguration sandboxMemoryConfiguaration, string guestBinaryPath, SandboxRunOptions runOptions, Action<ISandboxRegistration> initFunction = null) : this(sandboxMemoryConfiguaration, guestBinaryPath, runOptions, initFunction, null)
        {
        }

        public Sandbox(string guestBinaryPath, SandboxRunOptions runOptions, StringWriter writer = null) : this(SandboxMemoryConfiguration.Default, guestBinaryPath, runOptions, null, writer)
        {
        }

        public Sandbox(SandboxMemoryConfiguration sandboxMemoryConfiguaration, string guestBinaryPath, SandboxRunOptions runOptions, StringWriter writer = null) : this(sandboxMemoryConfiguaration, guestBinaryPath, runOptions, null, writer)
        {
        }
        public Sandbox(string guestBinaryPath, SandboxRunOptions runOptions, Action<ISandboxRegistration> initFunction, StringWriter writer = null) : this(SandboxMemoryConfiguration.Default, guestBinaryPath, runOptions, initFunction, writer)
        {
        }

        public Sandbox(SandboxMemoryConfiguration sandboxMemoryConfiguration, string guestBinaryPath, SandboxRunOptions runOptions, Action<ISandboxRegistration> initFunction = null, StringWriter writer = null)
        {
            if (!IsSupportedPlatform)
            {
                throw new PlatformNotSupportedException("Hyperlight is not supported on this platform");
            }

            if (!File.Exists(guestBinaryPath))
            {
                throw new ArgumentException($"Cannot find file {guestBinaryPath} to load into hyperlight");
            }
            this.writer = writer;
            this.guestBinaryPath = guestBinaryPath;

            this.recycleAfterRun = (runOptions & SandboxRunOptions.RecycleAfterRun) == SandboxRunOptions.RecycleAfterRun;
            this.runFromProcessMemory = (runOptions & SandboxRunOptions.RunInProcess) == SandboxRunOptions.RunInProcess ||
                                        (runOptions & SandboxRunOptions.RunFromGuestBinary) == SandboxRunOptions.RunFromGuestBinary;
            this.runFromGuestBinary = (runOptions & SandboxRunOptions.RunFromGuestBinary) == SandboxRunOptions.RunFromGuestBinary;

            // TODO: should we make this work?
            if (recycleAfterRun && runFromGuestBinary)
            {
                throw new ArgumentException("Cannot run from guest binary and recycle after run at the same time");
            }

            this.guestInterfaceGlue = new HyperlightGuestInterfaceGlue(this);

            this.sandboxMemoryManager = new SandboxMemoryManager(sandboxMemoryConfiguration, runFromProcessMemory);

            LoadGuestBinary();
            SetUpHyperLightPEB();

            // If we are NOT running from process memory, we have to setup a Hypervisor partition
            if (!runFromProcessMemory)
            {
                if (IsHypervisorPresent())
                {
                    SetUpHyperVisorPartition();
                }
                else
                {
                    throw new ArgumentException("Hypervisor not found");
                }
            }

            Initialise();

            initFunction?.Invoke(this);

            if (recycleAfterRun)
            {
                sandboxMemoryManager.SnapshotState();
            }

            initialised = true;

        }

        internal object DispatchCallFromHost(string functionName, object[] args)
        {
            var pDispatchFunction = sandboxMemoryManager.GetPointerToDispatchFunction();

            if (pDispatchFunction == 0)
            {
                throw new ArgumentException($"{nameof(pDispatchFunction)} is null");
            }

            sandboxMemoryManager.WriteGuestFunctionCallDetails(functionName, args);

            if (runFromProcessMemory)
            {
                var callDispatchFunction = Marshal.GetDelegateForFunctionPointer<CallDispatchFunction>((IntPtr)pDispatchFunction);
                callDispatchFunction();
            }
            else
            {
                hyperVisor!.DispatchCallFromHost(pDispatchFunction);
            }

            CheckForGuestError();

            return sandboxMemoryManager.GetReturnValue();
        }

        public void CheckForGuestError()
        {
            var guestError = sandboxMemoryManager.GetGuestError();
            if (guestError is null)
            {
                return;
            }
            if (guestError.ErrorCode != GuestErrorCode.NO_ERROR)
            {
                if (guestError.ErrorCode == GuestErrorCode.OUTB_ERROR)
                {
                    var exception = sandboxMemoryManager.GetHostException();
                    if (exception != null)
                    {
                        if (exception.InnerException != null)
                        {
                            throw exception.InnerException;
                        }
                        throw exception;
                    }
                }
                var message = $"{guestError.ErrorCode}:{guestError.Message}";
                throw new HyperlightException(message);
            }
        }

        void LoadGuestBinary()
        {
            var peInfo = guestPEInfo.GetOrAdd(guestBinaryPath, (guestBinaryPath) => GetPEInfo(guestBinaryPath, sandboxMemoryManager.GuestCodeAddress));

            if (runFromGuestBinary)
            {
                if (!IsWindows)
                {
                    // If not on Windows runFromBinary doesn't mean anything because we cannot use LoadLibrary.
                    throw new NotImplementedException("RunFromBinary is only supported on Windows");
                }

                // LoadLibrary does not support multple independent instances of a binary beng loaded 
                // so we cannot support multiple instances using loadlibrary

                if (Interlocked.CompareExchange(ref isRunningFromGuestBinary, IS_RUNNING_FROM_GUEST_BINARY, 0) == 0)
                {
                    didRunFromGuestBinary = true;
                }
                else
                {
                    throw new ApplicationException("Only one instance of Sandbox is allowed when running from guest binary");
                }

                sandboxMemoryManager.LoadGuestBinaryUsingLoadLibrary(guestBinaryPath, peInfo);
            }
            else
            {
                sandboxMemoryManager.LoadGuestBinaryIntoMemory(peInfo);

            }
        }

        void SetUpHyperLightPEB()
        {
            hyperlightPEB = sandboxMemoryManager.SetUpHyperLightPEB();
            CreateHyperlightPEBInMemory();
        }

        private void CreateHyperlightPEBInMemory()
        {
            UpdateFunctionMap();
            hyperlightPEB.Create();
        }

        private void UpdateHyperlightPEBInMemory()
        {
            UpdateFunctionMap();
            hyperlightPEB.Update();
        }

        private void UpdateFunctionMap()
        {
            foreach (var mi in guestInterfaceGlue.MapHostFunctionNamesToMethodInfo.Values)
            {

                // Dont add functions that already exist in the PEB
                // TODO: allow overloaded functions

                if (hyperlightPEB.FunctionExists(mi.methodInfo.Name))
                {
                    continue;
                }

                // TODO: Add support for void return types
                if (mi.methodInfo.ReturnType != typeof(int))
                {
                    throw new ArgumentException("Only int return types are supported");
                }

                var parameterSignature = "";
                foreach (var pi in mi.methodInfo.GetParameters())
                {
                    if (pi.ParameterType == typeof(int))
                        parameterSignature += "i";
                    else if (pi.ParameterType == typeof(string))
                        parameterSignature += "$";
                    else
                        throw new ArgumentException("Only int and string parameters are supported");
                }

                hyperlightPEB.AddFunction(mi.methodInfo.Name, $"({parameterSignature})i", 0);
            }
        }



        public void SetUpHyperVisorPartition()
        {

            var rsp = sandboxMemoryManager.SetUpHyperVisorPartition();

            if (IsLinux)
            {
                hyperVisor = new KVM(sandboxMemoryManager.SourceAddress, SandboxMemoryConfiguration.PML4GuestAddress, sandboxMemoryManager.Size, sandboxMemoryManager.EntryPoint, rsp, HandleOutb, sandboxMemoryManager.GetPebAddress());
            }
            else if (IsWindows)
            {
                hyperVisor = new HyperV(sandboxMemoryManager.SourceAddress, SandboxMemoryConfiguration.PML4GuestAddress, sandboxMemoryManager.Size, sandboxMemoryManager.EntryPoint, rsp, HandleOutb, sandboxMemoryManager.GetPebAddress());
            }
            else
            {
                // Should never get here
                throw new NotSupportedException();
            }
        }

        private void Initialise()
        {
            var returnValue = 0;

            if (runFromProcessMemory)
            {
                if (IsLinux)
                {
                    // This code is unstable, it causes segmetation faults so for now we are throwing an exception if we try to run in process in Linux
                    // I think this is due to the fact that the guest binary is built for windows
                    // x64 compilation for windows uses fastcall which is different on windows and linux
                    // dotnet will default to the calling convention for the platform that the code is running on
                    // so we need to set the calling convention to the one that the guest binary is built for (windows x64 https://docs.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170)
                    // on linux however, this isn't possible (https://docs.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.callingconvention?view=net-6.0 )
                    // Alternatives:
                    // 1. we need to build the binary for windows and linux and then run the correct version for the platform that we are running on
                    // 2. alter the calling convention of the guest binary and then tell dotnet to use that calling convention
                    // the only option for this seems to be vectorcall https://docs.microsoft.com/en-us/cpp/cpp/vectorcall?view=msvc-170 (cdecl and stdcall are not possible using CL on x64 platform))    
                    // vectorcall is not supported by dotnet  (https://github.com/dotnet/runtime/issues/8300) 
                    // 3. write our own code to correct the calling convention
                    // 4. write epilog/prolog code in the guest binary.     
                    // also see https://www.agner.org/optimize/calling_conventions.pdf
                    // and https://eli.thegreenplace.net/2011/09/06/stack-frame-layout-on-x86-64/
                    // 

                    throw new NotSupportedException("Cannot run in process on Linux");
                    var callOutB = new CallOutb_Linux((_, _, value, port) => HandleOutb(port, value));
                    gCHandle = GCHandle.Alloc(callOutB);
                    sandboxMemoryManager.SetOutBAddress((long)Marshal.GetFunctionPointerForDelegate<CallOutb_Linux>(callOutB));
                    CallEntryPoint();

                }
                else if (IsWindows)
                {
                    var callOutB = new CallOutb_Windows((port, value) => HandleOutb(port, value));

                    gCHandle = GCHandle.Alloc(callOutB);
                    sandboxMemoryManager.SetOutBAddress((long)Marshal.GetFunctionPointerForDelegate<CallOutb_Windows>(callOutB));
                    CallEntryPoint();
                }
                else
                {
                    // Should never get here
                    throw new NotSupportedException();
                }
            }
            else
            {
                hyperVisor!.Initialise();
            }

            returnValue = sandboxMemoryManager.GetReturnValue();

            if (returnValue != 0)
            {
                //TODO: Convert this to a specific exception
                throw new ApplicationException($"Init Function Failed with error code:{returnValue}");
            }
        }

        unsafe void CallEntryPoint()
        {
            callEntryPoint = (delegate* unmanaged<IntPtr, int>)sandboxMemoryManager.EntryPoint;
            _ = callEntryPoint((IntPtr)sandboxMemoryManager.GetPebAddress());
        }

        /// <summary>
        /// Enables the host to call multiple functions in the Guest and have the sandbox state reset at the start of the call
        /// Ensures that only one call can be made concurrently
        /// </summary>
        /// <typeparam name="T">The return type of the function</typeparam>
        /// <param name="func">The function to be executed</param>
        /// <returns>T</returns>
        /// <exception cref="ArgumentNullException">func is null</exception>
        /// <exception cref="ApplicationException">a call to the guest is already in progress</exception>

        public T CallGuest<T>(Func<T> func)
        {
            ArgumentNullException.ThrowIfNull(func, nameof(func));
            var shouldRelease = false;
            try
            {
                if (Interlocked.CompareExchange(ref executingGuestCall, 1, 0) != 0)
                {
                    throw new ApplicationException("Guest call already in progress");
                }
                shouldRelease = true;
                ResetState();
                return func();
            }
            finally
            {
                if (shouldRelease)
                {
                    Interlocked.Exchange(ref executingGuestCall, 0);
                }
            }
        }

        /// <summary>
        /// This method is called by DynamicMethods generated to call guest functions.
        /// It first checks to see if the sadnbox has been initialised yet or if there is a CallGuest Method call in progress, if so it just
        /// returns false as there is no need to check state
        /// </summary>
        /// <returns></returns>
        /// <exception cref="ApplicationException"></exception>
        internal bool EnterDynamicMethod()
        {
            // Check if call is before initialisation is finished or invoked inside CallGuest<T>
            // is both cases there is no need to check state
            if (!initialised || executingGuestCall == 1)
            {
                return false;
            }

            if ((Interlocked.CompareExchange(ref executingGuestCall, 2, 0)) != 0)
            {
                throw new ApplicationException("Guest call already in progress");
            }
            return true;
        }

        internal void ExitDynamicMethod(bool shouldRelease)
        {
            if (shouldRelease)
            {
                Interlocked.Exchange(ref executingGuestCall, 0);
            }
        }

        internal void ResetState()
        {

            if (countRunCalls > 0 && !recycleAfterRun)
            {
                throw new ArgumentException("You must set option RecycleAfterRun when creating the Sandbox if you need to call a function in the guest more than once");
            }

            if (recycleAfterRun)
            {
                sandboxMemoryManager.RestoreState();
            }

            countRunCalls++;

        }

        internal void HandleOutb(ushort port, byte _)
        {
            try
            {
                switch (port)
                {

                    case 101: // call Function
                        {

                            var methodName = sandboxMemoryManager.GetHostCallMethodName();
                            ArgumentNullException.ThrowIfNull(methodName);
                            
                            if (!guestInterfaceGlue.MapHostFunctionNamesToMethodInfo.ContainsKey(methodName))
                            {
                                throw new ArgumentException($"{methodName}, Could not find host method name.");
                            }

                            var mi = guestInterfaceGlue.MapHostFunctionNamesToMethodInfo[methodName];
                            var parameters = mi.methodInfo.GetParameters();
                            var args = sandboxMemoryManager.GetHostCallArgs(parameters);
                            var returnFromHost = (int)guestInterfaceGlue.DispatchCallFromGuest(methodName, args);
                            sandboxMemoryManager.WriteResponseFromHostMethodCall(returnFromHost);
                            break;

                        }
                    case 100: // Write with no carriage return
                        {
                            var str = sandboxMemoryManager.ReadStringOutput();
                            if (this.writer != null)
                            {
                                writer.Write(str);
                            }
                            else
                            {
                                var oldColor = Console.ForegroundColor;
                                Console.ForegroundColor = ConsoleColor.Green;
                                Console.Write(str);
                                Console.ForegroundColor = oldColor;
                            }
                            break;
                        }
                }
            }
            catch (Exception ex)
            {
                // if this is running from a guest binary we can just rethrow the exception otherwise we need to persist the details and 
                // raise the error in the guest.
                if (runFromGuestBinary)
                {
                    throw;
                }
                sandboxMemoryManager.WriteOutbException(ex, port);
            }
        }

        public void ExposeHostMethods(Type type)
        {
            if (type == null)
            {
                throw new ArgumentNullException(nameof(type));
            }
            guestInterfaceGlue.ExposeAndBindMembers(type);
            UpdateHyperLightPEB();
        }

        public void ExposeAndBindMembers(object instance)
        {
            if (instance == null)
            {
                throw new ArgumentNullException(nameof(instance));
            }
            guestInterfaceGlue.ExposeAndBindMembers(instance);
            UpdateHyperLightPEB();
        }

        public void BindGuestFunction(string delegateName, object instance)
        {
            if (instance == null)
            {
                throw new ArgumentNullException(nameof(instance));
            }
            guestInterfaceGlue.BindGuestFunctionToDelegate(delegateName, instance);
        }

        public void ExposeHostMethod(string methodName, object instance)
        {
            if (instance == null)
            {
                throw new ArgumentNullException(nameof(instance));
            }
            guestInterfaceGlue.ExposeHostMethod(methodName, instance);
            UpdateHyperLightPEB();
        }

        public void ExposeHostMethod(string methodName, Type type)
        {
            if (type == null)
            {
                throw new ArgumentNullException(nameof(type));
            }
            guestInterfaceGlue.ExposeHostMethod(methodName, type);
            UpdateHyperLightPEB();
        }

        private void UpdateHyperLightPEB()
        {
            if (recycleAfterRun && initialised)
            {
                sandboxMemoryManager.RestoreState();
            }
            UpdateHyperlightPEBInMemory();
            if (recycleAfterRun && initialised)
            {
                sandboxMemoryManager.SnapshotState();
            }
        }

        public static bool IsHypervisorPresent()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                return LinuxKVM.IsHypervisorPresent();
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return WindowsHypervisorPlatform.IsHypervisorPresent();
            }
            return false;
        }

        static PEInfo GetPEInfo(string fileName, ulong hyperVisorCodeAddress)
        {
            lock (peInfoLock)
            {
                if (guestPEInfo.ContainsKey(fileName))
                {
                    return guestPEInfo[fileName];
                }
                return new PEInfo(fileName, hyperVisorCodeAddress);
            }
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    if (didRunFromGuestBinary)
                    {
                        Interlocked.Decrement(ref isRunningFromGuestBinary);
                    }

                    gCHandle?.Free();

                    sandboxMemoryManager?.Dispose();

                    hyperVisor?.Dispose();

                }

                disposedValue = true;
            }
        }

        public void Dispose()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }
}
