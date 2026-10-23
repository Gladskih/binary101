// DMD 2.100.2 -m32omf -g emits embedded NB09 CodeView for the external parser test.
module legacy_debug;
int sharedValue = 41;
int nextValue(int value) { return value + 1; }
int main() {
    auto local = nextValue(sharedValue);
    return local == 42 ? 0 : 1;
}
