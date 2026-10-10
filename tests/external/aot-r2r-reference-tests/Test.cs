static class Test
{
    static int failures;
    static int total;

    public static void Run(string name, Action action)
    {
        total++;
        try
        {
            action();
            Console.WriteLine($"PASS {name}");
        }
        catch (Exception error)
        {
            failures++;
            Console.Error.WriteLine($"FAIL {name}: {error}");
        }
    }

    public static void Equal<T>(T expected, T actual)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
            throw new Exception($"Expected {expected}, got {actual}");
    }

    public static void Throws<T>(Action action) where T : Exception
    {
        try { action(); }
        catch (T) { return; }
        throw new Exception($"Expected {typeof(T).Name}");
    }

    public static int ExitCode()
    {
        Console.WriteLine($"{total - failures}/{total} passed");
        return failures == 0 ? 0 : 1;
    }
}
