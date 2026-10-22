// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

using Hyperlight.Component;

static class RuntimeTests
{
    public static void Run()
    {
        Check.Throws<WireFormatException>(() => new WireReader([1, 0]).U32(), "truncated u32");
        Check.Throws<WireFormatException>(() => new WireReader([5, 0, 0, 0, (byte)'a']).String(), "truncated string");
        Check.Throws<WireFormatException>(() => new WireReader([2, 0, 0, 0, 0xc3, 0x28]).String(), "invalid UTF-8");
        Check.Throws<WireFormatException>(() => new WireReader([0x00, 0xd8, 0, 0]).Char(), "surrogate char");
        Check.Throws<WireFormatException>(() => new WireReader([0xff, 0xff, 0xff, 0x7f]).Length(), "oversized list");
        Check.Throws<WireFormatException>(() =>
        {
            var r = new WireReader([1, 2]);
            r.U8();
            r.End();
        }, "trailing bytes");

        Check.True(Option<byte[]?>.Some([1]) == Option<byte[]?>.Some([1]), "option compares lists");
        IReadOnlyList<byte> array = new byte[] { 1, 2 };
        IReadOnlyList<byte> list = new List<byte> { 1, 2 };
        Check.True(
            Structural.Equal(array, list) && Structural.Hash(array) == Structural.Hash(list),
            "equal byte collections hash alike");
        Check.True(Option<byte[]?>.Some([1]) != Option<byte[]?>.Some([2]), "option lists differ");
        Check.True(Option<byte[]?>.Some(null) != Option<byte[]?>.None, "some null differs from none");
        Check.True(Result<byte[], string>.FromOk([1]) == Result<byte[], string>.FromOk([1]), "result compares lists");
        Check.True(Result<string, string>.FromOk("x") != Result<string, string>.FromErr("x"), "ok differs from err");

        var ok = Result<uint, string>.FromOk(7);
        var err = Result<uint, string>.FromErr("e");
        Check.True(ok.Match(ok: v => v.ToString(), err: e => e) == "7", "result match ok");
        Check.True(err.Match(ok: v => v.ToString(), err: e => e) == "e", "result match err");
        var switched = "";
        err.Switch(ok: v => switched = "ok", err: e => switched = e);
        Check.True(switched == "e", "result switch err");
    }
}
