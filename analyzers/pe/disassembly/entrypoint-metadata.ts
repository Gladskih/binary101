"use strict";

import type {
  AnalyzePeEntrypointDisassemblyOptions,
  PeEntrypointDisassemblyReport
} from "./types.js";
import {
  IMAGE_FILE_MACHINE_AMD64,
  IMAGE_FILE_MACHINE_I386,
  getCanonicalPeMachine
} from "../machine.js";

export type ValidEntrypointMetadata = {
  bitness: 32 | 64;
  entrypointRva: number;
};

// Microsoft PE format: section flags and 32-bit RVA fields.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
export const IMAGE_SCN_MEM_EXECUTE = 0x20000000;
export const RVA_EXCLUSIVE_LIMIT = 0x1_0000_0000;
export const MAX_RVA = RVA_EXCLUSIVE_LIMIT - 1;

export const normalizeEntrypointRva = (value: number): number | null =>
  Number.isSafeInteger(value) && value >= 0 && value <= MAX_RVA ? value >>> 0 : null;

export const emptyEntrypointReport = (
  opts: AnalyzePeEntrypointDisassemblyOptions,
  issues: string[]
): PeEntrypointDisassemblyReport => ({
  bitness: opts.is64Bit ? 64 : 32,
  entrypointRva: normalizeEntrypointRva(opts.entrypointRva) ?? 0,
  bytesDecoded: 0,
  instructionCount: 0,
  blocks: [],
  issues
});

export const getHeaderRvaLimit = (opts: AnalyzePeEntrypointDisassemblyOptions): number => {
  const value = opts.headerRvaLimit ?? 0;
  return Number.isSafeInteger(value) && value > 0 ? Math.min(value, RVA_EXCLUSIVE_LIMIT) : 0;
};

export const validateEntrypointMetadata = (
  opts: AnalyzePeEntrypointDisassemblyOptions,
  issues: string[]
): ValidEntrypointMetadata | null => {
  const coffMachine = getCanonicalPeMachine(opts.coffMachine);
  if (coffMachine !== IMAGE_FILE_MACHINE_I386 && coffMachine !== IMAGE_FILE_MACHINE_AMD64) {
    issues.push(
      `Entrypoint disassembly is only supported for x86/x86-64 ` +
      `(Machine ${coffMachine.toString(16)}).`
    );
    return null;
  }
  const expected64Bit = coffMachine === IMAGE_FILE_MACHINE_AMD64;
  if (opts.is64Bit !== expected64Bit) {
    const machineName = expected64Bit ? "AMD64" : "I386";
    const reportedMode = opts.is64Bit ? "64-bit" : "32-bit";
    issues.push(
      `Machine is ${machineName} but optional header reports ${reportedMode} mode; ` +
      `entrypoint disassembly skipped.`
    );
    return null;
  }
  if (opts.imageBase < 0n) {
    issues.push("ImageBase is negative; entrypoint disassembly skipped.");
    return null;
  }
  if (!Number.isSafeInteger(opts.entrypointRva) || opts.entrypointRva > MAX_RVA) {
    issues.push("PE optional header entry point RVA is outside the 32-bit RVA range.");
    return null;
  }
  if (opts.entrypointRva <= 0) {
    issues.push("PE optional header does not define an entry point RVA.");
    return null;
  }
  return {
    bitness: expected64Bit ? 64 : 32,
    entrypointRva: opts.entrypointRva >>> 0
  };
};
