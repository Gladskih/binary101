#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <cstdio>
#include <cstdint>
#include <cwchar>

static_assert(sizeof(void*) == 8, "Build the checker for x64");
extern "C" long long call_probe(void* target, long long value);

// A VEH has no user-data parameter. Only the recorded calling thread handles these traps.
struct ProbeCapture {
    unsigned char* entry;
    unsigned char* checkpoint;
    unsigned char entryOriginal;
    unsigned char checkpointOriginal;
    DWORD thread;
    DWORD64 imageBase;
    PRUNTIME_FUNCTION runtime;
    unsigned traps;
    DWORD fault;
    DWORD64 expectedStack;
    DWORD64 expectedFrame;
    DWORD64 expectedReturn;
    DWORD64 stackBefore;
    DWORD64 stackAfter;
    bool stackMatches;
    bool frameMatches;
    bool returnMatches;
};
static ProbeCapture capture = {};

static void writeInstructionByte(unsigned char* address, unsigned char value) {
    *address = value;
    FlushInstructionCache(GetCurrentProcess(), address, 1);
}

static DWORD unwind(CONTEXT* context) {
    __try {
        void* handlerData = nullptr;
        DWORD64 establisher = 0;
        RtlVirtualUnwind(UNW_FLAG_NHANDLER, capture.imageBase, context->Rip,
            capture.runtime, context, &handlerData, &establisher, nullptr);
        return 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
}

static void rememberCaller(const CONTEXT& context) {
    // CALL pushes an eight-byte return address on Win64.
    // https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention
    capture.expectedStack = context.Rsp + 8;
    capture.expectedFrame = context.Rbp;
    capture.expectedReturn = *reinterpret_cast<const DWORD64*>(context.Rsp);
}

static void inspectContext(CONTEXT context) {
    capture.stackBefore = context.Rsp;
    capture.fault = unwind(&context);
    capture.stackAfter = context.Rsp;
    capture.stackMatches = context.Rsp == capture.expectedStack;
    capture.frameMatches = context.Rbp == capture.expectedFrame;
    capture.returnMatches = context.Rip == capture.expectedReturn;
}

static LONG CALLBACK onBreakpoint(EXCEPTION_POINTERS* exception) {
    const auto* record = exception->ExceptionRecord;
    if (record->ExceptionCode != EXCEPTION_BREAKPOINT ||
        (record->ExceptionAddress != capture.entry &&
         record->ExceptionAddress != capture.checkpoint) ||
        GetCurrentThreadId() != capture.thread) return EXCEPTION_CONTINUE_SEARCH;
    auto* point = static_cast<unsigned char*>(record->ExceptionAddress);
    writeInstructionByte(point,
        point == capture.entry ? capture.entryOriginal : capture.checkpointOriginal);
    CONTEXT context = *exception->ContextRecord;
    // INT3 reports the following RIP. Inspect the original instruction boundary.
    context.Rip = reinterpret_cast<DWORD64>(point);
    exception->ContextRecord->Rip = context.Rip;
    capture.traps++;
    if (point == capture.entry) {
        rememberCaller(context);
        if (capture.checkpoint != capture.entry) {
            writeInstructionByte(capture.checkpoint, 0xcc);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    // Both original bytes have been restored before Windows inspects the code.
    inspectContext(context);
    return EXCEPTION_CONTINUE_EXECUTION;
}

static bool resolveProbe(HMODULE module, unsigned long offset) {
    capture.entry = reinterpret_cast<unsigned char*>(GetProcAddress(module, "probe"));
    if (!capture.entry) return false;
    MODULEINFO image = {};
    if (!K32GetModuleInformation(GetCurrentProcess(), module, &image, sizeof(image))) return false;
    const auto address = reinterpret_cast<std::uintptr_t>(capture.entry);
    const auto imageStart = reinterpret_cast<std::uintptr_t>(image.lpBaseOfDll);
    if (address < imageStart || address - imageStart >= image.SizeOfImage) return false;
    capture.runtime = RtlLookupFunctionEntry(address, &capture.imageBase, nullptr);
    if (!capture.runtime || capture.imageBase != imageStart ||
        capture.runtime->BeginAddress != address - imageStart ||
        capture.runtime->EndAddress > image.SizeOfImage ||
        capture.runtime->EndAddress <= capture.runtime->BeginAddress ||
        offset >= capture.runtime->EndAddress - capture.runtime->BeginAddress) return false;
    capture.checkpoint = capture.entry + offset;
    capture.entryOriginal = *capture.entry;
    capture.checkpointOriginal = *capture.checkpoint;
    capture.thread = GetCurrentThreadId();
    return capture.entryOriginal != 0xcc && capture.checkpointOriginal != 0xcc;
}

static bool runProbe(unsigned long offset) {
    void* handler = AddVectoredExceptionHandler(1, onBreakpoint);
    if (!handler) return false;
    DWORD previous = 0;
    if (!VirtualProtect(capture.entry, offset + 1, PAGE_EXECUTE_READWRITE, &previous)) {
        RemoveVectoredExceptionHandler(handler);
        return false;
    }
    writeInstructionByte(capture.entry, 0xcc);
    // probe(41) computes (41 + 1) ^ 42, which is zero.
    const long long result = call_probe(capture.entry, 41);
    writeInstructionByte(capture.entry, capture.entryOriginal);
    writeInstructionByte(capture.checkpoint, capture.checkpointOriginal);
    DWORD ignored = 0;
    const BOOL restored = VirtualProtect(capture.entry, offset + 1, previous, &ignored);
    RemoveVectoredExceptionHandler(handler);
    std::printf("traps=%u functionResult=%lld\n", capture.traps, result);
    return restored && capture.traps == (offset ? 2u : 1u) && result == 0;
}

static int report(unsigned long offset) {
    std::printf("checkpoint=%lu fault=%lu rspDelta=%lld expectedDelta=%lld "
        "rspOk=%u rbpOk=%u ripOk=%u\n", offset, capture.fault,
        static_cast<long long>(capture.stackAfter - capture.stackBefore),
        static_cast<long long>(capture.expectedStack - capture.stackBefore),
        static_cast<unsigned>(capture.stackMatches),
        static_cast<unsigned>(capture.frameMatches),
        static_cast<unsigned>(capture.returnMatches));
    return capture.fault == 0 && capture.stackMatches &&
        capture.frameMatches && capture.returnMatches ? 0 : 1;
}

static int check(HMODULE module, unsigned long offset) {
    if (!resolveProbe(module, offset) || !runProbe(offset)) {
        std::fprintf(stderr, "Probe setup, capture, or normal return failed\n");
        return 2;
    }
    return report(offset);
}

int wmain(int count, wchar_t** args) {
    if (count < 2 || count > 3) {
        std::fprintf(stderr, "usage: entry-check.exe path-to-probe.dll [checkpoint-offset]\n");
        return 2;
    }
    wchar_t* end = nullptr;
    const auto offset = count == 3 ? std::wcstoul(args[2], &end, 0) : 0;
    // The supplied fixtures are small. Offsets must identify instruction boundaries.
    if (count == 3 && (!end || end == args[2] || *end || offset > 255)) return 2;
    HMODULE module = LoadLibraryW(args[1]);
    if (!module) {
        std::fprintf(stderr, "LoadLibrary failed: %lu\n", GetLastError());
        return 2;
    }
    const int result = check(module, offset);
    FreeLibrary(module);
    return result;
}
