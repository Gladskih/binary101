"use strict";

// Microsoft Learn documents these APIs as process/fail-fast terminators:
// ExitProcess:
// https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-exitprocess
// RaiseFailFastException:
// https://learn.microsoft.com/windows/win32/api/errhandlingapi/nf-errhandlingapi-raisefailfastexception
// C/C++ runtime termination functions:
// https://learn.microsoft.com/cpp/c-runtime-library/reference/exit-exit-exit
// https://learn.microsoft.com/cpp/c-runtime-library/reference/abort
// https://learn.microsoft.com/cpp/c-runtime-library/reference/quick-exit1
const NON_RETURNING_IMPORT_SYMBOLS = new Set([
  "abort",
  "exit",
  "exitprocess",
  "quick_exit",
  "raisefailfastexception"
]);

const normalizeImportSymbol = (value: string): string =>
  value.trim().toLowerCase().replace(/^_+/u, "").replace(/@\d+$/u, "");

export const isKnownNonReturningImport = (label: string): boolean => {
  const separator = label.lastIndexOf("!");
  if (separator <= 0 || separator === label.length - 1) return false;
  return NON_RETURNING_IMPORT_SYMBOLS.has(normalizeImportSymbol(label.slice(separator + 1)));
};
