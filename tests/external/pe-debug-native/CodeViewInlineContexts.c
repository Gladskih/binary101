static __forceinline int scale(int seed) {
    volatile int scaled = seed * 3;
    return scaled + seed;
}

__declspec(dllexport) int InspectInline(int seed) {
    return scale(seed) + scale(seed + 1);
}
