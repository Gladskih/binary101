"use strict";

import { parseAmd64ExceptionDirectory } from "./exception-amd64.js";
import { parseArm64ExceptionDirectory } from "./exception-arm64.js";
import { createEmptyExceptionDirectory, type PeExceptionDirectory } from "./exception-types.js";
import type { PeDataDirectory, RvaToOffset } from "./types.js";

// Microsoft PE format, "Machine Types":
// AMD64, ARM64, ARM64EC, and ARM64X are the PE/COFF machine values whose EXCEPTION
// directory formats this parser understands.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#machine-types
const IMAGE_FILE_MACHINE_AMD64 = 0x8664;
const IMAGE_FILE_MACHINE_ARM64 = 0xaa64;
const IMAGE_FILE_MACHINE_ARM64EC = 0xa641;
const IMAGE_FILE_MACHINE_ARM64X = 0xa64e;

const isArm64ExceptionMachine = (machine: number): boolean =>
  machine === IMAGE_FILE_MACHINE_ARM64 ||
  machine === IMAGE_FILE_MACHINE_ARM64EC ||
  machine === IMAGE_FILE_MACHINE_ARM64X;

export { createEmptyExceptionDirectory, type PeExceptionDirectory } from "./exception-types.js";

export async function parseExceptionDirectory(
  file: File,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  machine = IMAGE_FILE_MACHINE_AMD64
): Promise<PeExceptionDirectory | null> {
  if (machine === IMAGE_FILE_MACHINE_AMD64) {
    return parseAmd64ExceptionDirectory(file, dataDirs, rvaToOff);
  }
  if (isArm64ExceptionMachine(machine)) {
    return parseArm64ExceptionDirectory(file, dataDirs, rvaToOff);
  }
  const dir = dataDirs.find(directory => directory.name === "EXCEPTION");
  if (!dir?.rva) {
    return null;
  }
  return createEmptyExceptionDirectory([
    `Exception directory decoding is not implemented for machine 0x${machine.toString(16)}.`
  ]);
}
