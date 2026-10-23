"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import { parseAmd64ExceptionDirectory } from "./amd64/index.js";
import { parseArm64ExceptionDirectory } from "./arm64.js";
import { parseArmntExceptionDirectory } from "./armnt.js";
import { parseNativeAotX86ExceptionDirectory } from "./native-aot-x86.js";
import { parseReadyToRunX86ExceptionDirectory } from "./ready-to-run-x86.js";
import { createEmptyExceptionDirectory, type PeExceptionDirectory } from "./types.js";
import type { PeDataDirectory, PeWindowsOptionalHeader, RvaToOffset } from "../types.js";
import { parseNtRiscExceptionDirectory } from "./nt-risc-directory.js";
import { parseCeExceptionDirectory } from "./ce-directory.js";
import type { PeClrReadyToRun } from "../clr/ready-to-run-types.js";
import type { PeNativeAotAnalysis } from "../native-aot.js";
import {
  IMAGE_FILE_MACHINE_AMD64,
  IMAGE_FILE_MACHINE_ARM64,
  IMAGE_FILE_MACHINE_ARM64EC,
  IMAGE_FILE_MACHINE_ARM64X,
  IMAGE_FILE_MACHINE_ARMNT,
  IMAGE_FILE_MACHINE_I386
} from "../../coff/machine.js";
import {
  getCanonicalPeMachine
} from "../machine.js";

const isArm64ExceptionMachine = (machine: number): boolean =>
  machine === IMAGE_FILE_MACHINE_ARM64 ||
  machine === IMAGE_FILE_MACHINE_ARM64EC ||
  machine === IMAGE_FILE_MACHINE_ARM64X;

export { createEmptyExceptionDirectory, type PeExceptionDirectory } from "./types.js";

const parseManagedX86Exceptions = async (reader: FileRangeReader, dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset, readyToRun: PeClrReadyToRun | null | undefined,
  nativeAotCandidate: PeNativeAotAnalysis | null | undefined): Promise<PeExceptionDirectory | null> =>
  await parseReadyToRunX86ExceptionDirectory(reader, dataDirs, rvaToOff, readyToRun) ??
    parseNativeAotX86ExceptionDirectory(reader, dataDirs, rvaToOff, nativeAotCandidate);

const unsupportedExceptionDirectory = (dataDirs: PeDataDirectory[], machine: number): PeExceptionDirectory | null => {
  const directory = dataDirs.find(entry => entry.name === "EXCEPTION");
  if (!directory || (directory.rva === 0 && directory.size === 0)) return null;
  return createEmptyExceptionDirectory([directory.rva === 0
    ? "Exception directory has a non-zero size but RVA is 0."
    : `Exception directory decoding is not implemented for machine 0x${machine.toString(16)}.`]);
};

export async function parseExceptionDirectory(
  reader: FileRangeReader,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  machine = IMAGE_FILE_MACHINE_AMD64,
  readyToRun?: PeClrReadyToRun | null,
  nativeAotCandidate?: PeNativeAotAnalysis | null,
  header?: PeWindowsOptionalHeader
): Promise<PeExceptionDirectory | null> {
  const canonicalMachine = getCanonicalPeMachine(machine);
  if (canonicalMachine === IMAGE_FILE_MACHINE_I386) {
    const managed = await parseManagedX86Exceptions(reader, dataDirs, rvaToOff, readyToRun, nativeAotCandidate);
    if (managed) return managed;
  }
  if (canonicalMachine === IMAGE_FILE_MACHINE_AMD64) {
    return parseAmd64ExceptionDirectory(reader, dataDirs, rvaToOff);
  }
  if (canonicalMachine === IMAGE_FILE_MACHINE_ARMNT) {
    return parseArmntExceptionDirectory(reader, dataDirs, rvaToOff);
  }
  if (isArm64ExceptionMachine(canonicalMachine)) {
    return parseArm64ExceptionDirectory(reader, dataDirs, rvaToOff);
  }
  const ntRisc = await parseNtRiscExceptionDirectory(reader, dataDirs, rvaToOff, canonicalMachine, header);
  if (ntRisc) return ntRisc;
  const ce = await parseCeExceptionDirectory(reader, dataDirs, rvaToOff, canonicalMachine, header);
  if (ce) return ce;
  return unsupportedExceptionDirectory(dataDirs, machine);
}
