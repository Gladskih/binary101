// Native compiler reference for frame/local metadata. The DLL is never executed.
__declspec(dllexport) __declspec(noinline) int InspectLocals(int seed, int unused) {
    volatile int saved = seed + 7;
    int running = seed * 3;
    if (seed & 1) {
        int branch = running + saved;
        saved = branch;
    }
    return running + saved;
}
