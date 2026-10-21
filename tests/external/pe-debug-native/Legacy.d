module legacy_debug;
int sharedValue = 41;
int nextValue(int value) { return value + 1; }
int main() {
    auto local = nextValue(sharedValue);
    return local == 42 ? 0 : 1;
}
