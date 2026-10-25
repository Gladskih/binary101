// Two exported procedures provide independently readable image RVAs after linking.
// Build with CodeView debug information; the resulting DLL is never executed.
__declspec(dllexport) __declspec(noinline) int ProcedureFirst(int value) {
    return value + 17;
}

__declspec(dllexport) __declspec(noinline) int ProcedureSecond(int value) {
    return ProcedureFirst(value) * 3;
}
