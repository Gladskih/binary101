"use strict";

// Windows SDK winnt.h IMAGE_DYNAMIC_RELOCATION_* symbolic values.
// https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/winnt.h
const SYMBOL_NAMES = new Map<bigint, string>([
  [1n, "GUARD_RF_PROLOGUE"],
  [2n, "GUARD_RF_EPILOGUE"],
  [3n, "GUARD_IMPORT_CONTROL_TRANSFER"],
  [4n, "GUARD_INDIR_CONTROL_TRANSFER"],
  [5n, "GUARD_SWITCHTABLE_BRANCH"],
  [6n, "ARM64X"],
  [7n, "FUNCTION_OVERRIDE"]
]);

export const getDynamicRelocationSymbolName = (symbol: bigint): string =>
  SYMBOL_NAMES.get(symbol) ?? "UNKNOWN";
