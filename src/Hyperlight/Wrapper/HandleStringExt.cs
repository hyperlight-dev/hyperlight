using System;
using System.Reflection;
using System.Runtime.InteropServices;
using Hyperlight.Core;

namespace Hyperlight.Wrapper
{
    public static class NativeHandleWrapperStringExtensions
    {
        /// <summary>
        /// Determine whether hdl refrences a string
        /// </summary>
        /// <param name="hdl">the Handle to interrogate</param>
        /// <returns>true if hdl references a string, false otherwise</returns>
        public static bool IsString(this Handle hdl)
        {
            HyperlightException.ThrowIfNull(hdl, MethodBase.GetCurrentMethod()!.DeclaringType!.Name);
            return handle_is_string(hdl.ctx.ctx, hdl.handle);
        }

        /// <summary>
        /// Get the string from the given handle or throw an exception if it 
        /// was an error. You can check if the handle was an error prior
        /// to calling this function using IsString.
        /// </summary>
        /// <param name="hdl">
        /// the handle from which to get the error message
        /// </param>
        /// <returns>the string to which hdl refers</returns>
        public static string? GetString(this Handle hdl)
        {
            HyperlightException.ThrowIfNull(hdl, MethodBase.GetCurrentMethod()!.DeclaringType!.Name);
            var ptr = handle_get_raw_string(hdl.ctx.ctx, hdl.handle);
            var result = Marshal.PtrToStringAnsi(ptr);
            free_raw_string(ptr);
            return result;
        }

#pragma warning disable CA1707 // Remove the underscores from member name
#pragma warning disable CA5393 // Use of unsafe DllImportSearchPath value AssemblyDirectory

        [DllImport("hyperlight_host", SetLastError = false, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
        [return: MarshalAs(UnmanagedType.U1)]
        private static extern bool handle_is_string(NativeContext ctx, NativeHandle hdl);

        [DllImport("hyperlight_host", SetLastError = false, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
        private static extern bool free_raw_string(IntPtr ptr);


        [DllImport("hyperlight_host", SetLastError = false, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
        private static extern IntPtr handle_get_raw_string(NativeContext ctx, NativeHandle hdl);

#pragma warning restore CA5393 // Use of unsafe DllImportSearchPath value AssemblyDirectory
#pragma warning restore CA1707

    }
}