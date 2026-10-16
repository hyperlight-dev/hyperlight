// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

// Checks the C# bindings generated from wire.wit against the byte vectors
// that src/hyperlight_host/tests/component_wire_test.rs checks for the
// Rust bindings.

using System.Text;
using Hyperlight.Component;
using Hyperlight.Tests.Wire;
using Hyperlight.Tests.Wire.Test.Wire;
using Hyperlight.Tests.Wire.Test.Wire.Types;

sealed class WireTests
{
    private readonly Dictionary<string, byte[]> _vectors = File
        .ReadLines(Path.Combine(AppContext.BaseDirectory, "vectors.txt"))
        .Where(line => line.Length > 0 && !line.StartsWith('#'))
        .Select(line => line.Split(' '))
        .ToDictionary(parts => parts[0], parts => Convert.FromHexString(parts[1]));

    private readonly HashSet<string> _used = [];
    private readonly Guest _guest = new();
    private readonly WireComponent _component;

    private WireTests() => _component = new WireComponent(_guest);

    public static void Run()
    {
        var t = new WireTests();
        t.Exports();
        t.Imports();
        t.InvalidValues();
        foreach (var name in t._vectors.Keys.Except(t._used))
        {
            Check.True(false, $"vector {name} not checked");
        }
    }

    private static readonly Everything Full = new()
    {
        B = true,
        U8v = 0xab,
        S8v = -2,
        U16v = 0xbeef,
        S16v = -300,
        U32v = 0xdead_beef,
        S32v = -70_000,
        U64v = 0x0123_4567_89ab_cdef,
        S64v = -5_000_000_000,
        F32v = 1.5f,
        F64v = -2.25,
        C = new Rune(0x1F388),
        S = "héllo",
        Bytes = [1, 2, 3],
        Points = [new Point { X = 1, Y = 2 }, new Point { X = -3, Y = 4 }],
        Nested = [["a", "bc"], []],
        FixedBytes = [7, 8, 9],
        FixedPoints = [new Point { X = 5, Y = 6 }, new Point { X = 7, Y = 8 }],
        Maybe = "m",
        MaybeNum = 9,
        MaybeMaybe = Option<string?>.Some("mm"),
        Res = Result<Point, string>.FromOk(new Point { X = 10, Y = 11 }),
        ResUnit = Result<Unit, string>.FromOk(default),
        ResEmpty = Result<Unit, Unit>.FromOk(default),
        Tup = ("t", 12, new Point { X = 13, Y = 14 }),
        Shape = new Shape.Rect(new Point { X = 15, Y = 16 }),
        Color = Color.Green,
        Perms = Permissions.Read | Permissions.Exec,
        Many = ManyFlags.F0 | ManyFlags.F9,
        Tup8 = (1, 2, 3, 4, 5, 6, 7, 0x0809),
        MaybeMaybeNum = Option<uint?>.Some(17),
        Full = FullFlags.H0 | FullFlags.H31,
    };

    private static readonly Everything Alt = new()
    {
        B = false,
        U8v = byte.MaxValue,
        S8v = sbyte.MinValue,
        U16v = ushort.MaxValue,
        S16v = short.MinValue,
        U32v = uint.MaxValue,
        S32v = int.MinValue,
        U64v = ulong.MaxValue,
        S64v = long.MinValue,
        F32v = -0.0f,
        F64v = double.MaxValue,
        C = new Rune('a'),
        S = "",
        Bytes = [],
        Points = [],
        Nested = [],
        FixedBytes = [0, 0, 0],
        FixedPoints = [new Point { X = 0, Y = 0 }, new Point { X = 0, Y = 0 }],
        Maybe = null,
        MaybeNum = null,
        MaybeMaybe = Option<string?>.Some(null),
        Res = Result<Point, string>.FromErr("bad"),
        ResUnit = Result<Unit, string>.FromErr("e"),
        ResEmpty = Result<Unit, Unit>.FromErr(default),
        Tup = ("", 0, new Point { X = 0, Y = 0 }),
        Shape = new Shape.Named("n"),
        Color = Color.Blue,
        Perms = Permissions.None,
        Many = ManyFlags.F8,
        Tup8 = (byte.MaxValue, 0, 0, 0, 0, 0, 0, ushort.MaxValue),
        MaybeMaybeNum = Option<uint?>.Some(null),
        Full = FullFlags.None,
    };

    private static readonly Everything None = Alt with
    {
        MaybeMaybe = Option<string?>.None,
        MaybeMaybeNum = Option<uint?>.None,
        Full = (FullFlags)uint.MaxValue,
        Shape = new Shape.None(),
        Color = Color.Red,
        Perms = Permissions.Write,
    };

    private void Exports()
    {
        Echo("everything-full", _component.Echo.EchoEverything, Full);
        Echo("everything-alt", _component.Echo.EchoEverything, Alt);
        Echo("everything-none", _component.Echo.EchoEverything, None);
        Echo<Shape>("shape-none", _component.Echo.EchoShape, new Shape.None());
        Echo<Shape>("shape-circle", _component.Echo.EchoShape, new Shape.Circle(3));
        Echo<Shape>("shape-rect", _component.Echo.EchoShape, new Shape.Rect(new Point { X = 1, Y = -1 }));
        Echo<Shape>("shape-named", _component.Echo.EchoShape, new Shape.Named("x"));
        Echo<Shape>("shape-path", _component.Echo.EchoShape,
            new Shape.Path([new Point { X = 1, Y = 2 }, new Point { X = 3, Y = 4 }]));
        Echo<byte>("extra-ping", _component.Extra.Ping, 0xa5);
        Echo("string", _component.Echo.EchoString, "héllo, 世界 🎈");
        Echo<(uint, string)>("two-args", x => _component.Echo.TwoArgs(x.Item1, x.Item2), (5, "five"));

        _guest.Reply = [42, 0, 0, 0];
        Check.True(_component.Echo.NoArgs() == 42, "no-args result");
        Check.True(_guest.Args.Length == 0, "no-args arguments");

        _guest.Reply = [];
        _component.Echo.NoResult(9);
        CheckArgs("no-result");

        _guest.Reply = [0, .. Vector("run")];
        Check.True(_component.Run("go") == Result<string, string>.FromOk("go"), "run result");
        CheckArgs("run");
    }

    private void Imports()
    {
        var registry = new Registry();
        WireComponent.RegisterImports(registry, new HostImpl(), new WorldImpl());
        var sum = registry.Call("test:wire/host@0.1.0#add", Vector("host-add.0"), Vector("host-add.1"));
        Check.True(sum.AsSpan().SequenceEqual(Vector("host-add.result")), "host-add result");
        var log = registry.Call("test:wire/host@0.1.0#log", [2, 0, 0, 0, (byte)'h', (byte)'i'], [2]);
        Check.True(log.Length == 0, "log result");
        Check.True(registry.Call("now").AsSpan().SequenceEqual(Vector("now.result")), "now result");
    }

    private void InvalidValues()
    {
        _guest.Reply = [4, 0, 0, 0];
        Check.Throws<WireFormatException>(() => _component.Echo.EchoShape(new Shape.None()), "invalid variant tag");
        _guest.Reply = [2];
        Check.Throws<WireFormatException>(() => _component.Run(""), "invalid result tag");

        void Rejects<T>(Everything value, string what) where T : Exception =>
            Check.Throws<T>(() => _component.Echo.EchoEverything(value), what);
        Rejects<ArgumentException>(Full with { FixedBytes = [1] }, "fixed bytes length");
        Rejects<ArgumentException>(Full with { FixedPoints = [] }, "fixed list length");
        Rejects<ArgumentOutOfRangeException>(Full with { Color = (Color)3 }, "enum range");
        Rejects<ArgumentOutOfRangeException>(Full with { Perms = (Permissions)8 }, "flags range");
        Rejects<ArgumentNullException>(Full with { Points = null! }, "null list");
    }

    private byte[] Vector(string name)
    {
        _used.Add(name);
        return _vectors[name];
    }

    // A single argument uses the vector `name`. Several use `name.0`, `name.1` and so on.
    private void CheckArgs(string name)
    {
        var args = _guest.Args;
        if (args.Length == 1)
        {
            Check.True(args[0].AsSpan().SequenceEqual(Vector(name)), $"{name} encoding");
            return;
        }
        for (var i = 0; i < args.Length; i++)
        {
            Check.True(args[i].AsSpan().SequenceEqual(Vector($"{name}.{i}")), $"{name}.{i} encoding");
        }
    }

    // The guest returns the encoded arguments, so the result decodes to the value passed in.
    private void Echo<T>(string name, Func<T, T> call, T value)
    {
        var result = call(value);
        CheckArgs(name);
        Check.True(EqualityComparer<T>.Default.Equals(value, result), $"{name} decoding");
    }

    private sealed class HostImpl : IHost
    {
        public void Log(string message, byte @event)
        {
            if (message != "hi" || @event != 2)
            {
                throw new InvalidOperationException("log decoded wrong arguments");
            }
        }

        public Point Add(Point left, Point right) => new() { X = left.X + right.X, Y = left.Y + right.Y };
    }

    private sealed class WorldImpl : IWireImports
    {
        public ulong Now() => 7;
    }
}
