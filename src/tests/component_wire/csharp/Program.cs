// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

// Tests C# bindings generated from wire.wit and edge.wit, and the
// Hyperlight.Component runtime they use.

WireTests.Run();
EdgeTests.Run();
RuntimeTests.Run();
return Check.Report();

/// <summary>Counts failed checks so one run reports all of them.</summary>
static class Check
{
    private static int s_failures;

    public static void True(bool ok, string what)
    {
        if (!ok)
        {
            s_failures++;
            Console.Error.WriteLine($"FAIL: {what}");
        }
    }

    public static void Throws<T>(Action action, string what) where T : Exception
    {
        try
        {
            action();
            True(false, $"{what} did not throw");
        }
        catch (T)
        {
        }
    }

    public static int Report()
    {
        Console.WriteLine(s_failures == 0 ? "OK" : $"{s_failures} failures");
        return s_failures == 0 ? 0 : 1;
    }
}
