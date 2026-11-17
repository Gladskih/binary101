#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstdlib>

// Independent oracle: Windows unwinds known synthetic instruction-boundary
// contexts. No analyzed executable code is executed. Only our no-entry DLL loads.
int wmain(int count, wchar_t **args) {
  if (count < 2) return 2;
  HMODULE image = LoadLibraryW(args[1]);
  if (!image) return 3;
  const auto function = (DWORD64)GetProcAddress(image, "PrologPush");
  if (!function) return 4;
  const unsigned allocation = count > 2 ? (unsigned)_wtoi(args[2]) : 40;
  unsigned failures = 0;
  const unsigned checkpoints[] = { 0u, 1u, 5u, 6u, 11u };
  for (unsigned offset : checkpoints) {
    alignas(16) DWORD64 stack[128] = {};
    const auto entry = (DWORD64)&stack[64];
    const DWORD64 original = 0x123456789abcdef0ull;
    stack[64] = 0x12345678;
    stack[63] = original;
    CONTEXT context = {};
    context.ContextFlags = CONTEXT_FULL;
    context.Rip = function + offset;
    context.Rbx = offset >= 11 ? 123 : original;
    context.Rsp = entry - (offset >= 1 ? 8 : 0) - (offset >= 5 ? allocation : 0);
    DWORD64 base = 0;
    const auto runtime = RtlLookupFunctionEntry(context.Rip, &base, nullptr);
    if (!runtime) return 5;
    void *handlerData = nullptr;
    DWORD64 establisher = 0;
    RtlVirtualUnwind(UNW_FLAG_NHANDLER, base, context.Rip, runtime, &context,
      &handlerData, &establisher, nullptr);
    const bool correct = context.Rsp == entry + 8 && context.Rip == 0x12345678 &&
      context.Rbx == original;
    failures += !correct;
    std::printf("{\"offset\":%u,\"allocation\":%u,\"ok\":%s,\"rspDelta\":%lld}\n",
      offset, allocation, correct ? "true" : "false", (long long)(context.Rsp - entry));
  }
  FreeLibrary(image);
  return failures ? 1 : 0;
}
