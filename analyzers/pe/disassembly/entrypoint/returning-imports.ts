"use strict";

const RETURNING_IMPORT_DLLS = new Set([
  "api-ms-win-core-processthreads-l1-1-0",
  "api-ms-win-core-processthreads-l1-1-1",
  "api-ms-win-core-file-l1-1-0",
  "api-ms-win-core-file-l1-2-0",
  "api-ms-win-core-processenvironment-l1-1-0",
  "api-ms-win-core-processenvironment-l1-2-0",
  "api-ms-win-core-sysinfo-l1-1-0",
  "api-ms-win-core-sysinfo-l1-2-0",
  "api-ms-win-crt-runtime-l1-1-0",
  "api-ms-win-crt-stdio-l1-1-0",
  "api-ms-win-crt-string-l1-1-0",
  "api-ms-win-crt-string-l1-1-1",
  "kernel32",
  "kernelbase",
  "msvcp140",
  "ucrtbase",
  "ucrtbased"
]);

// Microsoft Learn documents these as ordinary returning Win32 query functions:
// GetSystemTimeAsFileTime/GetTickCount64:
// https://learn.microsoft.com/windows/win32/api/sysinfoapi/
// GetCurrentProcessId/GetCurrentThreadId:
// https://learn.microsoft.com/windows/win32/api/processthreadsapi/
// IsProcessorFeaturePresent:
// https://learn.microsoft.com/windows/win32/api/processthreadsapi/
// GetModuleHandleA/W:
// https://learn.microsoft.com/windows/win32/api/libloaderapi/
// GetStdHandle:
// https://learn.microsoft.com/windows/console/getstdhandle
// WriteFile:
// https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-writefile
// CRT startup helpers:
// https://learn.microsoft.com/cpp/c-runtime-library/reference/initterm-initterm-e
// https://learn.microsoft.com/cpp/c-runtime-library/internal-crt-globals-and-functions
// puts:
// https://learn.microsoft.com/cpp/c-runtime-library/reference/puts-putws
// strlen:
// https://learn.microsoft.com/cpp/c-runtime-library/reference/
// std::ios_base::good:
// https://learn.microsoft.com/cpp/standard-library/ios-base-class
// std::basic_ios::clear/basic_ostream::flush:
// https://learn.microsoft.com/cpp/standard-library/basic-ios-class
// https://learn.microsoft.com/cpp/standard-library/basic-ostream-class
// MSVC STL basic_ostream::_Osfx is a void wrap-up helper declared in __msvc_ostream.hpp.
// std::uncaught_exception:
// https://learn.microsoft.com/cpp/standard-library/exception-functions
// _cexit/_c_exit:
// https://learn.microsoft.com/cpp/c-runtime-library/reference/cexit-c-exit
const RETURNING_IMPORT_SYMBOLS = new Set([
  "?_osfx@?$basic_ostream@du?$char_traits@d@std@@@std@@qaexxz",
  "?clear@?$basic_ios@du?$char_traits@d@std@@@std@@qaexh_n@z",
  "?flush@?$basic_ostream@du?$char_traits@d@std@@@std@@qaeaav12@xz",
  "?good@ios_base@std@@qbe_nxz",
  "?uncaught_exception@std@@ya_nxz",
  "c_exit",
  "cexit",
  "getcurrentprocess",
  "getcurrentprocessid",
  "getcurrentthread",
  "getcurrentthreadid",
  "getmodulehandlea",
  "getmodulehandlew",
  "getstdhandle",
  "getsystemtimeasfiletime",
  "getsystemtimepreciseasfiletime",
  "gettickcount",
  "gettickcount64",
  "get_initial_narrow_environment",
  "initterm",
  "initterm_e",
  "isprocessorfeaturepresent",
  "p___argc",
  "p___argv",
  "puts",
  "queryperformancecounter",
  "queryperformancefrequency",
  "register_thread_local_exe_atexit_callback",
  "strlen",
  "writefile"
]);

const normalizeDllName = (value: string): string =>
  value.trim().toLowerCase().replace(/\.dll$/u, "");

const normalizeImportSymbol = (value: string): string =>
  value.trim().toLowerCase().replace(/^_+/u, "").replace(/@\d+$/u, "");

export const isKnownReturningImport = (label: string): boolean => {
  const separator = label.lastIndexOf("!");
  if (separator <= 0 || separator === label.length - 1) return false;
  return (
    RETURNING_IMPORT_DLLS.has(normalizeDllName(label.slice(0, separator))) &&
    RETURNING_IMPORT_SYMBOLS.has(normalizeImportSymbol(label.slice(separator + 1)))
  );
};
