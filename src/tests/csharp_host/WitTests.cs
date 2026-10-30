// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

// Runs the C# bindings for witguest's guest.wit against witguest. Its
// exports call the matching host imports, so each round trip encodes and
// decodes in both directions.

using System.Collections;
using System.Reflection;
using System.Text;
using Hyperlight.Component;
using Hyperlight.Tests.Wit;
using Hyperlight.Tests.Wit.Test.Wit;
using Hyperlight.Tests.Wit.Test.Wit.HostResource;
using Hyperlight.Tests.Wit.Test.Wit.Roundtrip;

static class WitTests
{
    public static void Run()
    {
        using var sandbox = new TestSandbox(TestSandbox.WitGuest);
        var host = new Host();
        var resources = TestComponent.RegisterImports(sandbox, host, host, host);
        sandbox.Evolve();
        var component = new TestComponent(sandbox, resources);

        Primitives(component.Roundtrip);
        Lists(component.Roundtrip);
        Composites(component.Roundtrip);
        HostArguments(component.Roundtrip);
        Resources(component.TestHostResource, host);
        WorldFunctions(component);
        // A trap can leave the sandbox unusable, so it runs last.
        try
        {
            component.Failable.WillTrap();
            Check.True(false, "guest trap did not throw");
        }
        catch (SandboxException e)
        {
            Check.True(e.Message.Contains("deliberate guest crash"), $"guest trap: {e.Message}");
        }
    }

    private static void Same<T>(Func<T, T> call, T value, string what) =>
        Check.True(DeepEqual(call(value), value), $"{what}: {value}");

    // Compares lists by element and other values by their fields, since
    // records compare lists by reference.
    private static bool DeepEqual(object? a, object? b)
    {
        if (Equals(a, b))
        {
            return true;
        }
        if (a is null || b is null || a is string || b is string)
        {
            return false;
        }
        if (a is IEnumerable ea && b is IEnumerable eb)
        {
            var la = ea.Cast<object?>().ToList();
            var lb = eb.Cast<object?>().ToList();
            return la.Count == lb.Count && la.Zip(lb).All(p => DeepEqual(p.First, p.Second));
        }
        if (a.GetType() != b.GetType())
        {
            return false;
        }
        const BindingFlags fields = BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic;
        return a.GetType().GetFields(fields).All(f => DeepEqual(f.GetValue(a), f.GetValue(b)));
    }

    private static void Primitives(RoundtripExports r)
    {
        foreach (var x in new[] { false, true }) Same(r.RoundtripBool, x, "bool");
        foreach (var x in new[] { sbyte.MinValue, -2, sbyte.MaxValue }) Same(r.RoundtripS8, (sbyte)x, "s8");
        foreach (var x in new[] { short.MinValue, -300, short.MaxValue }) Same(r.RoundtripS16, (short)x, "s16");
        foreach (var x in new[] { int.MinValue, -70_000, int.MaxValue }) Same(r.RoundtripS32, x, "s32");
        foreach (var x in new[] { long.MinValue, -5_000_000_000, long.MaxValue }) Same(r.RoundtripS64, x, "s64");
        foreach (var x in new[] { 0, 0xab, byte.MaxValue }) Same(r.RoundtripU8, (byte)x, "u8");
        foreach (var x in new[] { 0, 0xbeef, ushort.MaxValue }) Same(r.RoundtripU16, (ushort)x, "u16");
        foreach (var x in new uint[] { 0, 0xdead_beef, uint.MaxValue }) Same(r.RoundtripU32, x, "u32");
        foreach (var x in new ulong[] { 0, 0x0123_4567_89ab_cdef, ulong.MaxValue }) Same(r.RoundtripU64, x, "u64");
        foreach (var x in new[] { 1.5f, -0.0f, float.MaxValue, float.NegativeInfinity }) Same(r.RoundtripF32, x, "f32");
        foreach (var x in new[] { -2.25, double.MaxValue, double.Epsilon }) Same(r.RoundtripF64, x, "f64");
        foreach (var x in new[] { new Rune('a'), new Rune(0xe9), new Rune(0x1F388) }) Same(r.RoundtripChar, x, "char");
        foreach (var x in new[] { "", "héllo, 世界 🎈" }) Same(r.RoundtripString, x, "string");
    }

    private static void Lists(RoundtripExports r)
    {
        Same<byte[]>(r.RoundtripList, [], "empty list");
        Same<byte[]>(r.RoundtripList, [1, 2, 3], "list");
        Same<byte[]>(r.RoundtripFixList, [1, 2, 3, 4], "fixed list");
        Same<IReadOnlyList<uint>>(r.RoundtripFixListU32, [0, 1, uint.MaxValue, 7], "fixed u32 list");
        Same<IReadOnlyList<ulong>>(r.RoundtripFixListU64, [0, 1, ulong.MaxValue, 7], "fixed u64 list");
        Same<IReadOnlyList<sbyte>>(r.RoundtripFixListI8, [sbyte.MinValue, -1, 0, sbyte.MaxValue], "fixed s8 list");
        Same<IReadOnlyList<short>>(r.RoundtripFixListI16, [short.MinValue, -1, 0, short.MaxValue], "fixed s16 list");
        Same<IReadOnlyList<int>>(r.RoundtripFixListI32, [int.MinValue, -1, 0, int.MaxValue], "fixed s32 list");
        Same<IReadOnlyList<long>>(r.RoundtripFixListI64, [long.MinValue, -1, 0, long.MaxValue], "fixed s64 list");
        Same<IReadOnlyList<float>>(r.RoundtripFixListF32, [1.5f, -1, 0, float.MaxValue], "fixed f32 list");
        Same<IReadOnlyList<double>>(r.RoundtripFixListF64, [1.5, -1, 0, double.MaxValue], "fixed f64 list");
        Same<byte[]>(r.RoundtripFixListU8Size8, [1, 2, 3, 4, 5, 6, 7, 8], "fixed list of 8");
        Same<IReadOnlyList<ulong>>(r.RoundtripFixListU64Size2, [1, ulong.MaxValue], "fixed list of 2");
        Same<IReadOnlyList<string>>(r.RoundtripFixListString, ["a", "", "bc", "🎈"], "fixed string list");
        Same<IReadOnlyList<byte[]>>(r.RoundtripFixArrayOfLists, [[1], [], [2, 3]], "fixed list of lists");
        Same<IReadOnlyList<IReadOnlyList<string>>>(r.RoundtripFixArrayOfStringLists, [["a", "bc"], []], "fixed list of string lists");
        Same<IReadOnlyList<IReadOnlyList<string>>>(r.RoundtripNestedList, [["a", "bc"], [], [""]], "nested list");
        Same<IReadOnlyList<Testrecord>>(r.RoundtripRecordList, [Record("a", 1), Record("", ulong.MaxValue)], "record list");
    }

    private static Testrecord Record(string contents, ulong length) => new() { Contents = contents, Length = length };

    private static void Composites(RoundtripExports r)
    {
        Same(r.RoundtripTuple, ("t", (byte)12), "tuple");
        foreach (var x in new[] { null, "", "m" }) Same(r.RoundtripOption, x, "option");
        foreach (var x in new[] { Option<string?>.None, Option<string?>.Some(null), Option<string?>.Some("mm") })
        {
            Same(r.RoundtripNestedOption, x, "nested option");
        }
        Same(r.RoundtripResult, Result<Rune, string>.FromOk(new Rune('x')), "ok");
        Same(r.RoundtripResult, Result<Rune, string>.FromErr("bad"), "err");
        Same(r.RoundtripResultUnit, Result<Unit, string>.FromOk(default), "ok unit");
        Same(r.RoundtripResultUnit, Result<Unit, string>.FromErr("e"), "err string");
        Same(r.RoundtripResultEmpty, Result<Unit, Unit>.FromOk(default), "empty ok");
        Same(r.RoundtripResultEmpty, Result<Unit, Unit>.FromErr(default), "empty err");
        Same(r.RoundtripRecord, Record("héllo", 0x0123_4567_89ab_cdef), "record");
        foreach (var x in new[] { Smallflags.None, Smallflags.FlagA | Smallflags.FlagC, (Smallflags)7 })
        {
            Same(r.RoundtripFlagsSmall, x, "small flags");
        }
        foreach (var x in new[] { Mediumflags.None, Mediumflags.M0 | Mediumflags.M9, Mediumflags.M8 })
        {
            Same(r.RoundtripFlagsMedium, x, "medium flags");
        }
        foreach (var x in new[] { Largeflags.None, Largeflags.Flag00 | Largeflags.Flag1f, (Largeflags)uint.MaxValue })
        {
            Same(r.RoundtripFlagsLarge, x, "large flags");
        }
        foreach (var x in new Testvariant[]
        {
            new Testvariant.VariantA(),
            new Testvariant.VariantB("b"),
            new Testvariant.VariantC(new Rune(0x1F388)),
            new Testvariant.VariantD(Record("d", 4)),
        })
        {
            Same(r.RoundtripVariant, x, "variant");
        }
        foreach (var x in Enum.GetValues<Testenum>()) Same(r.RoundtripEnum, x, "enum");

        var full = new Testcomposite
        {
            Nested = Option<uint?>.Some(17),
            Records = [Record("a", 1), Record("b", 2)],
            Fixed = [7, 8, 9],
            Res = Result<Testrecord, string>.FromOk(Record("ok", 10)),
            Tup = ("t", 12, Record("tup", 14)),
            Choice = new Testvariant.VariantD(Record("v", 16)),
            Kind = Testenum.EnumB,
            Mask = Mediumflags.M1 | Mediumflags.M8,
            C = new Rune(0x1F388),
            B = true,
        };
        Same(r.RoundtripComposite, full, "composite");
        Same(r.RoundtripComposite, full with
        {
            Nested = Option<uint?>.Some(null),
            Records = [],
            Res = Result<Testrecord, string>.FromErr("bad"),
            Choice = new Testvariant.VariantA(),
            Mask = Mediumflags.None,
            B = false,
        }, "composite alternative");
        Same(r.RoundtripComposite, full with { Nested = Option<uint?>.None }, "composite none");

        Check.True(r.RoundtripTwoArgs(5, "five") == (5, "five"), "two arguments");
        Check.True(r.RoundtripNoArgs() == 42, "no arguments");
        r.RoundtripNoResult(9);
    }

    // The bindings check values that C# types allow but WIT types do not.
    private static void HostArguments(RoundtripExports r)
    {
        Check.Throws<ArgumentException>(() => r.RoundtripFixList([1]), "fixed list length");
        Check.Throws<ArgumentException>(() => r.RoundtripFixListU32([]), "fixed list length");
        Check.Throws<ArgumentOutOfRangeException>(() => r.RoundtripEnum((Testenum)3), "enum range");
        Check.Throws<ArgumentOutOfRangeException>(() => r.RoundtripFlagsSmall((Smallflags)8), "flags range");
        Check.Throws<ArgumentNullException>(() => r.RoundtripList(null!), "null list");
        Check.Throws<ArgumentNullException>(() => r.RoundtripRecord(null!), "null record");
    }

    // witguest appends a, b and c to a resource made with "str" and 'z'.
    private static void Resources(TestHostResourceExports t, Host host)
    {
        Check.True(t.TestUsesLocally(), "uses locally");
        Check.True(host.Made.Count == 1 && host.Made[0].ToString() == "strabc c", "used locally");

        var r = t.TestMakes();
        Check.True(host.Made.Count == 2 && ReferenceEquals(r, host.Made[1]), "made by the guest");
        t.TestAcceptsBorrow(r);
        t.TestAcceptsOwn(r);
        var returned = t.TestReturns();
        Check.True(ReferenceEquals(returned, r), "returned to the host");
        Check.True(r.ToString() == "strabc c", "passed in and out");
    }

    private static void WorldFunctions(TestComponent c)
    {
        Check.True(c.Run("go") == Result<string, string>.FromOk("go 7"), "run");
        Check.True(c.Run("") == Result<string, string>.FromErr("empty input"), "run error");
        Check.True(c.Extra.Ping(0xa5) == 0xa5, "inline interface");
    }

    private sealed class Resource(string x, Rune last) : ITestresource
    {
        private readonly StringBuilder _x = new(x);
        private Rune _last = last;

        public void AppendChar(Rune c)
        {
            _x.Append(c.ToString());
            _last = c;
        }

        public override string ToString() => $"{_x} {_last}";
    }

    private sealed class Host : IRoundtrip, IHostResource, ITestImports
    {
        public List<ITestresource> Made { get; } = [];

        public ITestresource NewTestresource(string init1, Rune init2)
        {
            var r = new Resource(init1, init2);
            Made.Add(r);
            return r;
        }

        public ITestresource RoundtripOwn(ITestresource x) => x;
        public void ReturnOwn(ITestresource x) { }

        public ulong Now() => 7;

        public bool RoundtripBool(bool x) => x;
        public sbyte RoundtripS8(sbyte x) => x;
        public short RoundtripS16(short x) => x;
        public int RoundtripS32(int x) => x;
        public long RoundtripS64(long x) => x;
        public byte RoundtripU8(byte x) => x;
        public ushort RoundtripU16(ushort x) => x;
        public uint RoundtripU32(uint x) => x;
        public ulong RoundtripU64(ulong x) => x;
        public float RoundtripF32(float x) => x;
        public double RoundtripF64(double x) => x;
        public Rune RoundtripChar(Rune x) => x;
        public string RoundtripString(string x) => x;
        public byte[] RoundtripList(byte[] x) => x;
        public (string, byte) RoundtripTuple((string, byte) x) => x;
        public string? RoundtripOption(string? x) => x;
        public Result<Rune, string> RoundtripResult(Result<Rune, string> x) => x;
        public void RoundtripNoResult(uint x) { }
        public byte[] RoundtripFixList(byte[] x) => x;
        public IReadOnlyList<uint> RoundtripFixListU32(IReadOnlyList<uint> x) => x;
        public IReadOnlyList<ulong> RoundtripFixListU64(IReadOnlyList<ulong> x) => x;
        public IReadOnlyList<sbyte> RoundtripFixListI8(IReadOnlyList<sbyte> x) => x;
        public IReadOnlyList<short> RoundtripFixListI16(IReadOnlyList<short> x) => x;
        public IReadOnlyList<int> RoundtripFixListI32(IReadOnlyList<int> x) => x;
        public IReadOnlyList<long> RoundtripFixListI64(IReadOnlyList<long> x) => x;
        public IReadOnlyList<float> RoundtripFixListF32(IReadOnlyList<float> x) => x;
        public IReadOnlyList<double> RoundtripFixListF64(IReadOnlyList<double> x) => x;
        public byte[] RoundtripFixListU8Size8(byte[] x) => x;
        public IReadOnlyList<ulong> RoundtripFixListU64Size2(IReadOnlyList<ulong> x) => x;
        public IReadOnlyList<string> RoundtripFixListString(IReadOnlyList<string> x) => x;
        public IReadOnlyList<byte[]> RoundtripFixArrayOfLists(IReadOnlyList<byte[]> x) => x;
        public IReadOnlyList<IReadOnlyList<string>> RoundtripFixArrayOfStringLists(IReadOnlyList<IReadOnlyList<string>> x) => x;
        public Testrecord RoundtripRecord(Testrecord x) => x;
        public Smallflags RoundtripFlagsSmall(Smallflags x) => x;
        public Largeflags RoundtripFlagsLarge(Largeflags x) => x;
        public Testvariant RoundtripVariant(Testvariant x) => x;
        public Testenum RoundtripEnum(Testenum x) => x;
        public Mediumflags RoundtripFlagsMedium(Mediumflags x) => x;
        public Option<string?> RoundtripNestedOption(Option<string?> x) => x;
        public IReadOnlyList<IReadOnlyList<string>> RoundtripNestedList(IReadOnlyList<IReadOnlyList<string>> x) => x;
        public IReadOnlyList<Testrecord> RoundtripRecordList(IReadOnlyList<Testrecord> x) => x;
        public Result<Unit, string> RoundtripResultUnit(Result<Unit, string> x) => x;
        public Result<Unit, Unit> RoundtripResultEmpty(Result<Unit, Unit> x) => x;
        public (uint, string) RoundtripTwoArgs(uint first, string second) => (first, second);
        public uint RoundtripNoArgs() => 42;
        public Testcomposite RoundtripComposite(Testcomposite x) => x;
    }
}
