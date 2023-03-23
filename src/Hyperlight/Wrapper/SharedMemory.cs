using System;
using System.Runtime.InteropServices;
using Hyperlight.Core;

namespace Hyperlight.Wrapper
{
    public class SharedMemory : IDisposable
    {
        private readonly ulong size;
        internal ulong Size => size;
        private readonly Context ctxWrapper;
        public Handle handleWrapper { get; private set; }
        private bool disposed;
        public IntPtr Address
        {
            get
            {
                var addr = shared_memory_get_address(
                    this.ctxWrapper.ctx,
                    this.handleWrapper.handle
                );
                return (IntPtr)addr;
            }
        }

        /// <summary>
        /// Create a new SharedMemory instance with the given size
        /// </summary>
        /// <param name="ctx">the Context with which to do the create</param>
        /// <param name="size">the desired memory size</param>
        public SharedMemory(
            Context ctx,
            ulong size
        )
        {
            this.ctxWrapper = ctx;
            this.size = size;
            this.handleWrapper = new Handle(
                this.ctxWrapper,
                shared_memory_new(
                    this.ctxWrapper.ctx,
                    size
                )
            );
            this.handleWrapper.ThrowIfError();
        }

        /// <summary>
        /// Create a new wrapper class for an existing SharedMemory handle
        /// </summary>
        /// <param name="ctx">
        /// the context inside which the SharedMemory is stored
        /// </param>
        /// <param name="getterFn">
        /// the function to get the raw Handle to the SharedMemory
        /// </param>
        /// <exception cref="HyperlightException">
        /// if any given parameters are null, or there was an error creating
        /// the new SharedMemory
        /// </exception>
        internal SharedMemory(
            Context ctx,
            Func<Context, NativeHandle> getterFn
        )
        {

            HyperlightException.ThrowIfNull(
                ctx,
                nameof(ctx),
                GetType().Name
            );
            HyperlightException.ThrowIfNull(
                getterFn,
                nameof(getterFn),
                GetType().Name
            );
            this.ctxWrapper = ctx;
            this.handleWrapper = new Handle(ctx, getterFn(ctx), true);
            var sizeRawHdl = shared_memory_get_size(ctx.ctx, this.handleWrapper.handle);
            using var sizeHdl = new Handle(ctx, sizeRawHdl, true);
            if (!sizeHdl.IsUInt64())
            {
                throw new HyperlightException(
                    "couldn't get the size of given shared memory handle"
                );
            }
            var size = sizeHdl.GetUInt64();
            this.size = size;
        }

        // TODO: make this a long rather than ulong
        public void WriteInt64(
            IntPtr addr,
            ulong val
        )
        {
            var rawHdl = shared_memory_write_int_64(
                this.ctxWrapper.ctx,
                this.handleWrapper.handle,
                (ulong)addr.ToInt64(),
                val
            );
            using (var hdl = new Handle(this.ctxWrapper, rawHdl))
            {
                hdl.ThrowIfError();
            }
        }

        public long ReadInt64(
            UIntPtr addr
        )
        {
            var rawHdl = shared_memory_read_int_64(
                this.ctxWrapper.ctx,
                this.handleWrapper.handle,
                addr.ToUInt64()
            );
            using (var hdl = new Handle(this.ctxWrapper, rawHdl))
            {

                hdl.ThrowIfError();
                return hdl.GetInt64();
            }
        }
        public void WriteInt32(
            IntPtr offset,
            int val
        )
        {
            var hdlRes = shared_memory_write_int_32(
                this.ctxWrapper.ctx,
                this.handleWrapper.handle,
                (ulong)offset.ToInt64(),
                val
            );
            using (var hdlWrapper = new Handle(this.ctxWrapper, hdlRes))
            {
                hdlWrapper.ThrowIfError();
            }
        }

        public int ReadInt32(
            UIntPtr offset
        )
        {
            var rawHdl = shared_memory_read_int_32(
                this.ctxWrapper.ctx,
                this.handleWrapper.handle,
                offset.ToUInt64()
            );
            using (var hdl = new Handle(this.ctxWrapper, rawHdl))
            {
                hdl.ThrowIfError();
                return hdl.GetInt32();
            }
        }

        public void CopyFromByteArray(
            byte[] arr,
            IntPtr offset
        )
        {
            HyperlightException.ThrowIfNull(arr, GetType().Name);

            using var barr = new ByteArray(this.ctxWrapper, arr);
            this.CopyFromByteArray(
                barr,
                (ulong)offset.ToInt64(),
                0,
                (ulong)arr.Length
            );
        }

        public void CopyToByteArray(
            byte[] arr,
            ulong offset
        )
        {
            HyperlightException.ThrowIfNull(arr, GetType().Name);

            var rawHdl = shared_memory_copy_to_byte_array(
                this.ctxWrapper.ctx,
                this.handleWrapper.handle,
                offset,
                arr,
                (ulong)arr.Length
            );
            using (var hdl = new Handle(this.ctxWrapper, rawHdl))
            {
                hdl.ThrowIfError();
            }
        }

        public byte[] CopyAllToByteArray()
        {
            var outArr = new byte[this.size];
            this.CopyToByteArray(outArr, 0);
            return outArr;
        }


        public void CopyFromByteArray(
            ByteArray arr,
            ulong addr,
            ulong arrStart,
            ulong arrLength
        )
        {
            HyperlightException.ThrowIfNull(arr, GetType().Name);

            var rawHdl = shared_memory_copy_from_byte_array(
                this.ctxWrapper.ctx,
                this.handleWrapper.handle,
                arr.handleWrapper.handle,
                addr,
                arrStart,
                arrLength
            );
            using (var hdl = new Handle(this.ctxWrapper, rawHdl))
            {
                hdl.ThrowIfError();
            }
        }


        public void Dispose()
        {
            this.Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!this.disposed)
            {
                if (disposing)
                {
                    this.handleWrapper.Dispose();
                }
                this.disposed = true;
            }
        }
#pragma warning disable CA1707 // Remove the underscores from member name
#pragma warning disable CA1401 // P/Invoke method should not be visible
#pragma warning disable CA5393 // Use of unsafe DllImportSearchPath value AssemblyDirectory

        [DllImport("hyperlight_host", SetLastError = false, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
        public static extern NativeHandle shared_memory_new(
            NativeContext ctx,
            ulong size
        );

        [DllImport("hyperlight_host", SetLastError = false, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
        public static extern ulong shared_memory_get_address(
            NativeContext ctx,
            NativeHandle hdl
        );

        [DllImport("hyperlight_host", SetLastError = false, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
        public static extern ulong shared_memory_get_size(
            NativeContext ctx,
            NativeHandle hdl
        );

        [DllImport("hyperlight_host", SetLastError = false, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
        public static extern NativeHandle shared_memory_copy_from_byte_array(
            NativeContext ctx,
            NativeHandle shared_memory_handle,
            NativeHandle byte_array_handle,
            ulong address,
            ulong arr_start,
            ulong arr_length
        );

        [DllImport("hyperlight_host", SetLastError = false, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
        public static extern NativeHandle shared_memory_copy_to_byte_array(
            NativeContext ctx,
            NativeHandle shared_memory_handle,
            ulong offset,
            [In, Out][MarshalAs(UnmanagedType.LPArray)] byte[] arr,
            ulong arr_length
        );

        [DllImport("hyperlight_host", SetLastError = false, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
        public static extern NativeHandle shared_memory_write_int_64(
            NativeContext ctx,
            NativeHandle shared_memory_handle,
            ulong address,
            ulong val
        );

        [DllImport("hyperlight_host", SetLastError = false, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
        public static extern NativeHandle shared_memory_read_int_32(
            NativeContext ctx,
            NativeHandle shared_memory_handle,
            ulong address
        );

        [DllImport("hyperlight_host", SetLastError = false, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
        public static extern NativeHandle shared_memory_read_int_64(
            NativeContext ctx,
            NativeHandle shared_memory_handle,
            ulong address
        );

        [DllImport("hyperlight_host", SetLastError = false, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
        public static extern NativeHandle shared_memory_write_int_32(
            NativeContext ctx,
            NativeHandle shared_memory_handle,
            ulong address,
            int val
        );
    }

#pragma warning disable CA5393 // Use of unsafe DllImportSearchPath value AssemblyDirectory
#pragma warning disable CA1401 // P/Invoke method should not be visible
#pragma warning restore CA1707
}
