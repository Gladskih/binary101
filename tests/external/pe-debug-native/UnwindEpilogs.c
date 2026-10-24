// MSVC /O2 /GS- /d2epilogunwind emits multiple v2 epilog scopes.
// The output is inspected statically and never executed.
__declspec(noinline) int helper(int value) { return value + 1; }

__declspec(dllexport) int entry(int count) {
    volatile int values[100];
    values[0] = helper(count);
    if (count < 0) return values[0] + 1;
    if (count == 0) return values[0] + 2;
    return values[0] + 3;
}
