// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

// Checks the naming and type cases in edge.wit.

using System.Runtime.CompilerServices;
using Hyperlight.Tests.Edge;
using Hyperlight.Tests.Edge.Test.Edge;
using Hyperlight.Tests.Edge.Test.Edge.Shared;
using Hyperlight.Tests.Edge.Test.Edge.Types;
using Dep1 = Hyperlight.Tests.Edge.Test.Dep.V1_0_0;
using Dep2 = Hyperlight.Tests.Edge.Test.Dep.V2_0_0;

static class EdgeTests
{
    public static void Run()
    {
        var guest = new Guest();
        var component = new EdgeComponent(guest);

        void Sent(string function, byte[] args, string what) =>
            Check.True(guest.Function == function && guest.Args.Length == 1 && guest.Args[0].SequenceEqual(args), what);

        // Fields named like their record or like object members get a suffix.
        var r = new R { R_ = 1, ToString_ = 2 };
        Check.True(component.Ops.Keyword(@class: r) == r, "keyword round trip");
        Sent("test:edge/ops#keyword", [1, 2], "keyword encoding");
        Check.True(r.ToString().Contains("ToString_ = 2"), "record ToString");

        foreach (var type in new[] { typeof(R), typeof(P), typeof(Lists) })
        {
            Check.True(type.GetProperties().All(p => p.IsDefined(typeof(RequiredMemberAttribute), false)), $"{type.Name} required");
        }

        // Aliases resolve to the type they name.
        IReadOnlyList<P> points = [new P { X = 1 }, new P { X = 2 }];
        Check.True(component.Ops.Alias(points).SequenceEqual(points), "alias round trip");
        Sent("test:edge/ops#alias", [2, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0], "alias encoding");

        // Lists inside records round trip.
        var lists = new Lists { Id = 1, Names = ["a", "b"], Pair = (2, [3, 4]) };
        var back = component.Ops.NestedLists(lists);
        Check.True(
            back.Id == 1 && back.Names.SequenceEqual(lists.Names) && back.Pair.Item1 == 2 && back.Pair.Item2.SequenceEqual(lists.Pair.Item2),
            "lists round trip");

        // A case named like the Value property or a keyword gets an escaped name.
        static string Describe(V v) => v switch
        {
            V.None => "none",
            V.Class c => $"class {c.Value}",
            V.Items i => $"items {i.Value.Count}",
            V.Value_ x => $"value {x.Value}",
            _ => "unknown",
        };
        V[] cases = [new V.None(), new V.Class("c"), new V.Value_(9), new V.Items([1, 2])];
        string[] expected = ["none", "class c", "value 9", "items 2"];
        for (var i = 0; i < cases.Length; i++)
        {
            Check.True(Describe(component.Ops.Cases(cases[i])) == expected[i], $"{expected[i]} round trip");
        }
        Sent("test:edge/ops#cases", [2, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0], "items encoding");

        Check.True(component.Ops.Single(new ValueTuple<ushort>(0x1234)).Item1 == 0x1234, "single tuple round trip");
        Sent("test:edge/ops#single", [0x34, 0x12], "single tuple encoding");

        component.Other.G();
        Check.True(guest.Function == "other#g" && guest.Args.Length == 0, "inline interface call");

        // Exports named like members of the component class get escaped names.
        component.RegisterImports_.R();
        Check.True(guest.Function == "register-imports#r", "export named register-imports");
        component.EdgeComponent_.C();
        Check.True(guest.Function == "edge-component#c", "export named like the component class");

        // The world-level export `shared` is a method, so the property for
        // the interface `shared` is qualified with its package.
        var s = new S { X = 4 };
        Check.True(component.TestEdgeShared.Echo(s) == s, "exported shared round trip");
        Sent("test:edge/shared#echo", [4, 0, 0, 0], "shared encoding");
        component.Shared();
        Check.True(guest.Function == "shared", "world function beside an interface property");
        guest.Reply = [7, 0, 0, 0];
        Check.True(component.TestEdgeShared.ToString_() == 7, "exported to-string");
        component.World.W();
        Check.True(guest.Function == "test:edge/world#w", "interface named world");

        // Named arguments check the generated parameter names. Each version of
        // an imported package, and each package of a name that loses its dash,
        // has its own parameter.
        var registry = new Registry();
        var shared = new SharedHost();
        EdgeComponent.RegisterImports(
            registry,
            testDepV1_0_0T: new DepV1(),
            testDepV2_0_0T: new DepV2(),
            shared: shared,
            a_BCTypes: new BcTypes(),
            aB_CTypes: new AbTypes());
        Check.True(registry.Call("test:dep/t@1.0.0#f", [5, 0, 0, 0]).SequenceEqual(new byte[] { 105, 0, 0, 0 }), "dep 1.0.0");
        Check.True(registry.Call("test:dep/t@2.0.0#f", [5, 0, 0, 0]).SequenceEqual(new byte[] { 205, 0, 0, 0 }), "dep 2.0.0");
        Check.True(registry.Call("test:edge/shared#echo", [6, 0, 0, 0]).SequenceEqual(new byte[] { 6, 0, 0, 0 }), "imported shared echo");
        registry.Call("test:edge/shared#finalize");
        Check.True(shared.Finalized, "imported finalize");
        Check.True(registry.Call("test:edge/shared#to-string").SequenceEqual(new byte[] { 3, 0, 0, 0 }), "imported to-string");
        Check.True(registry.Call("a:b-c/types#f").SequenceEqual(new byte[] { 1 }), "a:b-c types");
        Check.True(registry.Call("a-b:c/types#g").SequenceEqual(new byte[] { 2 }), "a-b:c types");
    }

    // Imported functions named like inherited members get a suffix.
    sealed class SharedHost : IShared
    {
        public bool Finalized;

        public S Echo(S x) => x;

        public void Finalize_() => Finalized = true;

        public uint ToString_() => 3;
    }

    sealed class BcTypes : Hyperlight.Tests.Edge.A.BC.ITypes
    {
        public byte F() => 1;
    }

    sealed class AbTypes : Hyperlight.Tests.Edge.AB.C.ITypes
    {
        public byte G() => 2;
    }

    sealed class DepV1 : Dep1.IT
    {
        public uint F(Dep1.T.R x) => x.X + 100;
    }

    sealed class DepV2 : Dep2.IT
    {
        public uint F(Dep2.T.R x) => x.X + 200;
    }
}
