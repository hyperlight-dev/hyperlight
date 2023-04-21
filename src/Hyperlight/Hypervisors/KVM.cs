using System;
using System.Reflection;
using System.Runtime.InteropServices;
using Hyperlight.Core;
using Hyperlight.Native;
using Hyperlight.Wrapper;

namespace Hyperlight.Hypervisors
{
    internal sealed class KVM : Hypervisor, IDisposable
    {
        readonly int kvm = -1;
        readonly IntPtr pRun = IntPtr.Zero;
        readonly int vcpufd = -1;
        readonly int vmfd = -1;
        internal KVM(IntPtr sourceAddress, ulong pml4_addr, ulong size, ulong entryPoint, ulong rsp, Action<ushort, byte> outb, Action handleMemoryAccess) : base(sourceAddress, entryPoint, rsp, outb, handleMemoryAccess)
        {
            if (!LinuxKVM.IsHypervisorPresent())
            {
                HyperlightException.LogAndThrowException("KVM Not Present", GetType().Name);
            }

            if (-1 == (kvm = LinuxKVM.open("/dev/kvm", LinuxKVM.O_RDWR | LinuxKVM.O_CLOEXEC)))
            {
                HyperlightException.LogAndThrowException("Unable to open '/dev/kvm'", GetType().Name);
            }

            vmfd = LinuxKVM.ioctl(kvm, LinuxKVM.KVM_CREATE_VM, 0);
            if (-1 == vmfd)
            {
                HyperlightException.LogAndThrowException("KVM_CREATE_VM returned -1", GetType().Name);
            }

            var region = new LinuxKVM.KVM_USERSPACE_MEMORY_REGION() { slot = 0, guest_phys_addr = (ulong)SandboxMemoryLayout.BaseAddress, memory_size = size, userspace_addr = (ulong)sourceAddress };
            Syscall.CheckReturnVal(
                "ioctl KVM_SET_USER_MEMORY_REGION",
                () => LinuxKVM.ioctl(vmfd, LinuxKVM.KVM_SET_USER_MEMORY_REGION, ref region),
                0
            );

            vcpufd = LinuxKVM.ioctl(vmfd, LinuxKVM.KVM_CREATE_VCPU, 0);
            if (-1 == vcpufd)
            {
                HyperlightException.LogAndThrowException("KVM_CREATE_VCPU returned -1", GetType().Name);
            }

            var mmap_size = LinuxKVM.ioctl(kvm, LinuxKVM.KVM_GET_VCPU_MMAP_SIZE, 0);
            if (-1 == mmap_size)
            {
                HyperlightException.LogAndThrowException("KVM_GET_VCPU_MMAP_SIZE returned -1", GetType().Name);
            }

            // TODO: According to https://www.kernel.org/doc/html/latest/virt/kvm/api.html#general-description ioctls on a vcpu should occur on the same thread that created the vcpu. 
            // Otherwise, there could be a performance impact.

            pRun = OS.mmap(IntPtr.Zero, (ulong)mmap_size, OS.PROT_READ | OS.PROT_WRITE, OS.MAP_SHARED, vcpufd, 0);
            var sregs = new LinuxKVM.KVM_SREGS();
            Syscall.CheckReturnVal(
                "ioctl KVM_GET_SREGS",
                () => LinuxKVM.ioctl(vcpufd, LinuxKVM.KVM_GET_SREGS, ref sregs),
                0
            );

            sregs.cr3 = (ulong)pml4_addr;
            sregs.cr4 = X64.CR4_PAE | X64.CR4_OSFXSR | X64.CR4_OSXMMEXCPT;
            sregs.cr0 = X64.CR0_PE | X64.CR0_MP | X64.CR0_ET | X64.CR0_NE | X64.CR0_WP | X64.CR0_AM | X64.CR0_PG;
            sregs.efer = X64.EFER_LME | X64.EFER_LMA;

            var seg = new LinuxKVM.KVM_SEGMENT()
            {
                Base = 0,
                limit = 0xffffffff,
                selector = 1 << 3,
                present = 1,
                type = 11,
                dpl = 0,
                db = 0,
                s = 1,
                l = 1,
                g = 1
            };
            sregs.cs = seg;
            seg.type = 3;
            seg.selector = 2 << 3;
            sregs.ds = seg;
            sregs.es = seg;
            sregs.fs = seg;
            sregs.gs = seg;
            sregs.ss = seg;

            Syscall.CheckReturnVal(
                "ioctl KVM_SET_SREGS",
                () => LinuxKVM.ioctl(vcpufd, LinuxKVM.KVM_SET_SREGS, ref sregs),
                0
            );

        }
        private bool disposedValue;

        internal override void DispatchCallFromHost(ulong pDispatchFunction)
        {
            // Move rip to the DispatchFunction pointer
            var regs = new LinuxKVM.KVM_REGS();
            Syscall.CheckReturnVal(
                "ioctl KVM_GET_REGS",
                () => LinuxKVM.ioctl(
                    vcpufd,
                    LinuxKVM.KVM_GET_REGS,
                    ref regs
                ),
                0
            );
            regs.rip = pDispatchFunction;
            Syscall.CheckReturnVal(
                "ioctl KVM_SET_REGS",
                () => LinuxKVM.ioctl(vcpufd, LinuxKVM.KVM_SET_REGS, ref regs),
                0
            );
            ExecuteUntilHalt();
        }

        private void ExecuteUntilHalt()
        {
            while (true)
            {
                Syscall.CheckReturnVal(
                    "ioctl KVM_RUN_REQ",
                    () => LinuxKVM.ioctl(vcpufd, LinuxKVM.KVM_RUN_REQ, 0),
                    0
                );

                var run = Marshal.PtrToStructure<LinuxKVM.KVM_RUN>(pRun);
                switch (run.exit_reason)
                {
                    case LinuxKVM.KVM_EXIT_HLT:
                        return;
                    case LinuxKVM.KVM_EXIT_IO:
                        // TODO: reduce calls to get/set regs See https://www.kernel.org/doc/html/latest/virt/kvm/api.html#kvm-cap-sync-regs 
                        // Save rip, call HandleOutb, then restore rip
                        var regs = new LinuxKVM.KVM_REGS();
                        Syscall.CheckReturnVal(
                            "ioctl KVM_GET_REGS",
                            () => LinuxKVM.ioctl(vcpufd, LinuxKVM.KVM_GET_REGS, ref regs),
                            0
                        );
                        var ripOrig = regs.rip;
                        HandleOutb(run.port, Marshal.ReadByte(pRun, (int)run.data_offset));

                        // Restore rip
                        Syscall.CheckReturnVal(
                            "ioctl KVM_GET_REGS",
                            () => LinuxKVM.ioctl(vcpufd, LinuxKVM.KVM_GET_REGS, ref regs),
                            0
                        );
                        regs.rip = ripOrig + 1; //TODO: +1 is a hack, but it works for now, need to figure out how to get the instruction length;
                        Syscall.CheckReturnVal(
                            "ioctl KVM_SET_REGS",
                            () => LinuxKVM.ioctl(vcpufd, LinuxKVM.KVM_SET_REGS, ref regs),
                            0
                        );
                        break;
                    case LinuxKVM.KVM_EXIT_MMIO:
                        HandleMemoryAccess();
                        ThrowExitException(run, true);
                        break;
                    default:
                        ThrowExitException(run);
                        break;
                }
            }
        }

        private static void ThrowExitException(LinuxKVM.KVM_RUN run, bool known = false)
        {
            if (known)
            {
                HyperlightException.LogAndThrowException(
                    $"Known KVM exit_reason = {run.exit_reason}",
                    MethodBase.GetCurrentMethod()!.DeclaringType!.Name
                );
            }
            else
            {
                //TODO: Improve exception data;
                HyperlightException.LogAndThrowException(
                    $"Unknown KVM exit_reason = {run.exit_reason}",
                    MethodBase.GetCurrentMethod()!.DeclaringType!.Name
                );
            }
        }
        internal override void ResetRSP(ulong rsp)
        {
            // Move rip to the DispatchFunction pointer
            var regs = new LinuxKVM.KVM_REGS();
            Syscall.CheckReturnVal(
                "ioctl KVM_GET_REGS",
                () => LinuxKVM.ioctl(
                    vcpufd,
                    LinuxKVM.KVM_GET_REGS,
                    ref regs
                ),
                0
            );
            regs.rsp = rsp;
            Syscall.CheckReturnVal(
                "ioctl KVM_SET_REGS",
                () => LinuxKVM.ioctl(vcpufd, LinuxKVM.KVM_SET_REGS, ref regs),
                0
            );
        }

        internal override void Initialise(IntPtr pebAddress, ulong seed, uint pageSize)
        {
            var regs = new LinuxKVM.KVM_REGS()
            {
                rip = EntryPoint,
                rsp = rsp,
                r8 = (ulong)pageSize,
                rdx = seed,
                rcx = (ulong)pebAddress,
                rflags = 0x0002,
            };
            Syscall.CheckReturnVal(
                "ioctl KVM_SET_REGS",
                () => LinuxKVM.ioctl(vcpufd, LinuxKVM.KVM_SET_REGS, ref regs),
                0
            );
            ExecuteUntilHalt();
        }

        private void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    // TODO: dispose managed state (managed objects)
                }
                // TODO:Should the vcpufd and the vmfd be closed?
                // see: https://www.kernel.org/doc/html/latest/virt/kvm/api.html#file-descriptors

                if (vcpufd != -1)
                {
                    Syscall.CheckReturnVal(
                        "KVM close vcpufd",
                        () => LinuxKVM.close(vcpufd),
                        0
                    );
                }

                if (vmfd != -1)
                {
                    Syscall.CheckReturnVal(
                        "KVM close vmfd",
                        () => LinuxKVM.close(vmfd),
                        0
                    );
                }

                if (kvm != -1)
                {
                    Syscall.CheckReturnVal(
                        "KVM close kvm",
                        () => LinuxKVM.close(kvm),
                        0
                    );
                }

                disposedValue = true;
            }
        }

        ~KVM()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: false);
        }

        public override void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}
