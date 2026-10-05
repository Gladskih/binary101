using System.Diagnostics.CodeAnalysis;
using System.Reflection;

[AttributeUsage(AttributeTargets.All)]
public sealed class ExampleAttribute(int value) : Attribute
{
    public int Value { get; } = value;
    public string Name { get; set; } = "sample";
}

[Example(42, Name = "native metadata")]
public class Sample<T> where T : class, new()
{
    public const long Big = -123456789012345;
    public int Number = 12;
    public string Name { get; set; } = "AOT";
    public event EventHandler? Changed;
    public U Convert<U>(ref T input, U[] values, int[,] matrix, int count = 17)
        where U : struct => values[0];
    public void Raise() => Changed?.Invoke(this, EventArgs.Empty);
    public class Nested { public double Amount; }
}

public static class Program
{
    private static void Print([DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] Type type)
    {
        Console.WriteLine(type.FullName);
        foreach (var member in type.GetMembers(BindingFlags.Public | BindingFlags.NonPublic |
            BindingFlags.Instance | BindingFlags.Static)) Console.WriteLine(member);
    }

    public static void Main()
    {
        Print(typeof(Sample<>));
        Print(typeof(Sample<>.Nested));
        Print(typeof(ExampleAttribute));
    }
}
