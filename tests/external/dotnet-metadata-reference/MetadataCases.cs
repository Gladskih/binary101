// The compiler supplies real generic attribute and nested-enum metadata for differential tests.
[GenericValue<int>(-7)]
[GenericValue<string>("typed constructor")]
[NestedValue(MetadataCases.Mode.Enabled)]
static class MetadataCases
{
    public enum Mode : byte { Enabled = 1 }
}

[AttributeUsage(AttributeTargets.All, AllowMultiple = true)]
sealed class GenericValueAttribute<T>(T value) : Attribute
{
    public T Value { get; } = value;
}

sealed class NestedValueAttribute(MetadataCases.Mode mode) : Attribute
{
    public MetadataCases.Mode Mode { get; } = mode;
}
