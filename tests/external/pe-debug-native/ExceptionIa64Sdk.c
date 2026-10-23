// Read-only wire-layout oracle using unmodified Windows SDK types and DbgHelp.
// This validates the table, not the Windows IA64 unwind-descriptor language.
#include <windows.h>
#include <dbghelp.h>
#include <stdint.h>
#include <stdio.h>

static int print_table(void *base, SIZE_T file_size) {
    ULONG size = 0;
    PIMAGE_IA64_RUNTIME_FUNCTION_ENTRY rows = ImageDirectoryEntryToDataEx(
        base, FALSE, IMAGE_DIRECTORY_ENTRY_EXCEPTION, &size, NULL);
    uintptr_t offset = (uintptr_t)rows - (uintptr_t)base;
    if (!rows || offset > file_size || size > file_size - offset || size % sizeof(*rows)) {
        return 2;
    }
    printf("{\"entrySize\":%zu,\"rows\":[", sizeof(*rows));
    for (ULONG index = 0; index < size / sizeof(*rows); index++) {
        printf("%s[%lu,%lu,%lu]", index ? "," : "", rows[index].BeginAddress,
            rows[index].EndAddress, rows[index].UnwindInfoAddress);
    }
    printf("]}\n");
    return 0;
}

int wmain(int argc, wchar_t **argv) {
    if (argc != 2 || sizeof(IMAGE_IA64_RUNTIME_FUNCTION_ENTRY) != 12) return 1;
    HANDLE file = CreateFileW(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return 1;
    LARGE_INTEGER size;
    if (!GetFileSizeEx(file, &size) || size.QuadPart < sizeof(IMAGE_DOS_HEADER) ||
        size.QuadPart > MAXDWORD) {
        CloseHandle(file);
        return 1;
    }
    HANDLE mapping = CreateFileMappingW(file, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!mapping) { CloseHandle(file); return 1; }
    void *base = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
    int result = base ? print_table(base, (SIZE_T)size.QuadPart) : 1;
    if (base) UnmapViewOfFile(base);
    CloseHandle(mapping);
    CloseHandle(file);
    return result;
}
