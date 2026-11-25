// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

using Hyperlight.Component;

static class RuntimeTests
{
    public static void Run()
    {
        Check.Throws<ArgumentException>(() => new WireWriter().String("\ud800"), "lone surrogate");
        Check.True(Option<string?>.Some("a") == Option<string?>.Some("a"), "options equal");
        Check.True(Option<string?>.Some(null) != Option<string?>.None, "some null differs from none");
        Check.True(Result<string, string>.FromOk("x") != Result<string, string>.FromErr("x"), "ok differs from err");

        var table = new ResourceTable<string>();
        var aborted = new CallScope();
        var undone = table.Give("aborted", aborted);
        aborted.End();
        Check.Throws<WireFormatException>(() => table.Borrow(undone), "gift undone before the call");
        var started = new CallScope();
        var kept = table.Give("kept", started);
        started.Commit();
        started.End();
        Check.True(table.Take(kept) == "kept", "gift kept after the call starts");
        Check.True(table.Count == 0, "taken and undone entries are removed");

        var loan = new CallScope();
        var lent = table.Lend("lent", loan);
        Check.Throws<WireFormatException>(() => table.Take(lent), "lent value cannot be taken");
        loan.End();
        Check.True(table.Count == 0, "ended loans are removed");
        Check.Throws<WireFormatException>(() => table.Borrow(lent), "ended loan is invalid");
        Check.True(table.Give("next") > lent, "handles are not reused");
    }
}
