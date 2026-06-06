"use strict";

const RETURNING_IMPORT_DLLS = new Set([
  "api-ms-win-core-processthreads-l1-1-0",
  "api-ms-win-core-processthreads-l1-1-1",
  "api-ms-win-core-sysinfo-l1-1-0",
  "api-ms-win-core-sysinfo-l1-2-0",
  "kernel32",
  "kernelbase"
]);

// Microsoft Learn documents these as ordinary returning Win32 query functions:
// GetSystemTimeAsFileTime/GetTickCount64:
// https://learn.microsoft.com/windows/win32/api/sysinfoapi/
// GetCurrentProcessId/GetCurrentThreadId:
// https://learn.microsoft.com/windows/win32/api/processthreadsapi/
const RETURNING_IMPORT_SYMBOLS = new Set([
  "getcurrentprocess",
  "getcurrentprocessid",
  "getcurrentthread",
  "getcurrentthreadid",
  "getsystemtimeasfiletime",
  "getsystemtimepreciseasfiletime",
  "gettickcount",
  "gettickcount64",
  "queryperformancecounter",
  "queryperformancefrequency"
]);

const normalizeDllName = (value: string): string =>
  value.trim().toLowerCase().replace(/\.dll$/u, "");

export const isKnownReturningImport = (label: string): boolean => {
  const separator = label.lastIndexOf("!");
  if (separator <= 0 || separator === label.length - 1) return false;
  return (
    RETURNING_IMPORT_DLLS.has(normalizeDllName(label.slice(0, separator))) &&
    RETURNING_IMPORT_SYMBOLS.has(label.slice(separator + 1).trim().toLowerCase())
  );
};
