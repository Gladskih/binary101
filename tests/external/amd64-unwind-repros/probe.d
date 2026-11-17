extern(C) long probe(long value)
{
    return (value + 1) ^ 42;
}
