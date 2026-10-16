// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

using Hyperlight.Component;

/// <summary>
/// Records each call and returns the arguments concatenated, which echoes
/// a single argument. <see cref="Reply"/> replaces the next result.
/// </summary>
sealed class Guest : IGuestCaller
{
    public string Function = "";

    public byte[][] Args = [];

    public byte[]? Reply;

    public byte[] Call(string function, byte[][] args)
    {
        Function = function;
        Args = args;
        var result = Reply ?? args.SelectMany(a => a).ToArray();
        Reply = null;
        return result;
    }
}

sealed class Registry : IHostFunctionRegistry
{
    private readonly Dictionary<string, (int Count, Func<byte[][], byte[]> Function)> _functions = [];

    public void Register(string function, int parameterCount, Func<byte[][], byte[]> implementation) =>
        _functions.Add(function, (parameterCount, implementation));

    public byte[] Call(string function, params byte[][] args)
    {
        var (count, implementation) = _functions[function];
        if (count != args.Length)
        {
            throw new ArgumentException($"{function} takes {count} arguments");
        }
        return implementation(args);
    }
}
