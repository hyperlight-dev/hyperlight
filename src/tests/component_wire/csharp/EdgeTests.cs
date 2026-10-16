// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

// Checks the naming and type cases in edge.wit.

using System.Runtime.CompilerServices;
using Hyperlight.Tests.Edge;
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

        // Lists inside records and variant cases compare by element.
        Lists MakeLists(byte last) => new() { Id = 1, Names = ["a", "b"], Pair = (2, [3, last]) };
        var lists = MakeLists(4);
        Check.True(lists == MakeLists(4) && lists.GetHashCode() == MakeLists(4).GetHashCode(), "lists equal");
        Check.True(lists != MakeLists(5), "tuple bytes differ");
        Check.True(lists != (lists with { Names = ["a"] }), "names differ");
        Check.True(component.Ops.Structural(lists) == lists, "lists round trip");
        V items = new V.Items([1, 2]);
        Check.True(items == new V.Items([1, 2]) && items.GetHashCode() == new V.Items([1, 2]).GetHashCode(), "items equal");
        Check.True(items != new V.Items([1]), "items differ");

        // Cases named like Match or a keyword get escaped names and parameters.
        string Describe(V v) => v.Match(
            none: () => "none",
            match: m => $"match {m}",
            @class: c => $"class {c}",
            items: i => $"items {i.Count}");
        V[] cases = [new V.None(), new V.Match_(7), new V.Class("c"), items];
        string[] expected = ["none", "match 7", "class c", "items 2"];
        for (var i = 0; i < cases.Length; i++)
        {
            Check.True(Describe(cases[i]) == expected[i], $"match {expected[i]}");
            var switched = "";
            cases[i].Switch(
                none: () => switched = "none",
                match: m => switched = $"match {m}",
                @class: c => switched = $"class {c}",
                items: i => switched = $"items {i.Count}");
            Check.True(switched == expected[i], $"switch {expected[i]}");
            Check.True(component.Ops.Cases(cases[i]) == cases[i], $"{expected[i]} round trip");
        }
        Sent("test:edge/ops#cases", [3, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0], "items encoding");

        Check.True(component.Ops.Single(new ValueTuple<ushort>(0x1234)).Item1 == 0x1234, "single tuple round trip");
        Sent("test:edge/ops#single", [0x34, 0x12], "single tuple encoding");

        component.Other.G();
        Check.True(guest.Function == "other#g" && guest.Args.Length == 0, "inline interface call");

        // Each version of an imported package has its own namespace and wire name.
        var registry = new Registry();
        EdgeComponent.RegisterImports(registry, new DepV1(), new DepV2());
        Check.True(registry.Call("test:dep/t@1.0.0#f", [5, 0, 0, 0]).SequenceEqual(new byte[] { 105, 0, 0, 0 }), "dep 1.0.0");
        Check.True(registry.Call("test:dep/t@2.0.0#f", [5, 0, 0, 0]).SequenceEqual(new byte[] { 205, 0, 0, 0 }), "dep 2.0.0");
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
