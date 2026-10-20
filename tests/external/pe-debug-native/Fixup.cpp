// MSVC reference payload: compile /c /Zi /Od /GS-, link /debug /debugtype:cv,fixup
// /incremental:no /nodefaultlib /entry:entry /subsystem:console.
volatile int GlobalValue;
volatile int* GlobalPointer = &GlobalValue;
__declspec(noinline) int Transform(int value) { return value + 1; }
int entry() { return Transform(*GlobalPointer); }
