// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using Hyperlight.Component;

/// <summary>Thrown when the native test library reports an error.</summary>
sealed class SandboxException(string message) : Exception(message);

/// <summary>
/// A Hyperlight sandbox driven through the C API of
/// hyperlight-csharp-test-native. Register host functions, then
/// <see cref="Evolve"/>, then call guest functions.
/// </summary>
sealed unsafe class TestSandbox : IGuestCaller, IHostFunctionRegistry, IDisposable
{
    private const string Lib = "hyperlight_csharp_test_native";

    [StructLayout(LayoutKind.Sequential)]
    private struct Bytes
    {
        public byte* Ptr;
        public nuint Len;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct OwnedBytes
    {
        public byte* Ptr;
        public nuint Len;
    }

    [DllImport(Lib)]
    private static extern OwnedBytes hltest_sandbox_new(Bytes path, out nint sandbox);

    [DllImport(Lib)]
    private static extern void hltest_sandbox_free(nint sandbox);

    [DllImport(Lib)]
    private static extern OwnedBytes hltest_register(
        nint sandbox, Bytes name, nuint count, delegate* unmanaged<nint, Bytes*, nuint, nint, void> function, nint context);

    [DllImport(Lib)]
    private static extern void hltest_host_result(nint result, Bytes bytes, byte ok);

    [DllImport(Lib)]
    private static extern OwnedBytes hltest_evolve(nint sandbox);

    [DllImport(Lib)]
    private static extern OwnedBytes hltest_call(nint sandbox, Bytes name, Bytes* args, nuint count, out OwnedBytes result);

    [DllImport(Lib)]
    private static extern void hltest_bytes_free(OwnedBytes bytes);

    /// <summary>Path of the witguest binary for this build profile.</summary>
    public static string WitGuest => typeof(TestSandbox).Assembly
        .GetCustomAttributes<AssemblyMetadataAttribute>()
        .Single(a => a.Key == "WitGuest").Value!;

    private readonly List<GCHandle> _functions = [];
    private nint _sandbox;

    public TestSandbox(string guest)
    {
        var path = Encoding.UTF8.GetBytes(guest);
        fixed (byte* p = path)
        {
            Check(hltest_sandbox_new(new Bytes { Ptr = p, Len = (nuint)path.Length }, out _sandbox));
        }
    }

    public void Register(string function, int parameterCount, Func<byte[][], byte[]> implementation)
    {
        var handle = GCHandle.Alloc(implementation);
        _functions.Add(handle);
        var name = Encoding.UTF8.GetBytes(function);
        fixed (byte* p = name)
        {
            Check(hltest_register(_sandbox, new Bytes { Ptr = p, Len = (nuint)name.Length }, (nuint)parameterCount, &Invoke, GCHandle.ToIntPtr(handle)));
        }
    }

    public void Evolve() => Check(hltest_evolve(_sandbox));

    public byte[] Call(string function, byte[][] args)
    {
        var pins = args.Select(a => GCHandle.Alloc(a, GCHandleType.Pinned)).ToArray();
        try
        {
            var buffers = new Bytes[args.Length];
            for (var i = 0; i < args.Length; i++)
            {
                buffers[i] = new Bytes { Ptr = (byte*)pins[i].AddrOfPinnedObject(), Len = (nuint)args[i].Length };
            }
            var name = Encoding.UTF8.GetBytes(function);
            OwnedBytes result;
            fixed (byte* p = name)
            fixed (Bytes* a = buffers)
            {
                Check(hltest_call(_sandbox, new Bytes { Ptr = p, Len = (nuint)name.Length }, a, (nuint)buffers.Length, out result));
            }
            try
            {
                return new ReadOnlySpan<byte>(result.Ptr, (int)result.Len).ToArray();
            }
            finally
            {
                hltest_bytes_free(result);
            }
        }
        finally
        {
            foreach (var pin in pins)
            {
                pin.Free();
            }
        }
    }

    public void Dispose()
    {
        hltest_sandbox_free(_sandbox);
        _sandbox = 0;
        foreach (var handle in _functions)
        {
            handle.Free();
        }
        _functions.Clear();
    }

    private static void Check(OwnedBytes error)
    {
        if (error.Ptr is null)
        {
            return;
        }
        try
        {
            throw new SandboxException(Encoding.UTF8.GetString(error.Ptr, (int)error.Len));
        }
        finally
        {
            hltest_bytes_free(error);
        }
    }

    // Exceptions must not cross into native code, so they become error results.
    [UnmanagedCallersOnly]
    private static void Invoke(nint context, Bytes* args, nuint count, nint result)
    {
        byte[] bytes;
        byte ok = 1;
        try
        {
            var function = (Func<byte[][], byte[]>)GCHandle.FromIntPtr(context).Target!;
            var managed = new byte[(int)count][];
            for (var i = 0; i < managed.Length; i++)
            {
                managed[i] = new ReadOnlySpan<byte>(args[i].Ptr, (int)args[i].Len).ToArray();
            }
            bytes = function(managed);
        }
        catch (Exception e)
        {
            bytes = Encoding.UTF8.GetBytes(e.ToString());
            ok = 0;
        }
        fixed (byte* p = bytes)
        {
            hltest_host_result(result, new Bytes { Ptr = p, Len = (nuint)bytes.Length }, ok);
        }
    }
}
