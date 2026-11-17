module prolog_reference;

pragma(inline, false)
long leaf(long value) {
    return value * 3 + 1;
}

pragma(inline, false)
long frame(long seed) {
    long[2049] values = void;
    foreach (index; 0 .. values.length) {
        values[index] = seed + cast(long)index;
    }
    return values[seed & 2047] ^ leaf(seed);
}

int main(string[] args) {
    return cast(int)(frame(cast(long)args.length) & 255);
}
