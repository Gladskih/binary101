"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import { parseAmd64ExceptionDirectory } from "./amd64/index.js";
import { parseArm64ExceptionDirectory } from "./arm64.js";
import { parseReadyToRunX86ExceptionDirectory } from "./ready-to-run-x86.js";
import { createEmptyExceptionDirectory, type PeExceptionDirectory } from "./types.js";
import type { PeDataDirectory, RvaToOffset } from "../types.js";
import type { PeClrReadyToRun } from "../clr/ready-to-run-types.js";
import {
  IMAGE_FILE_MACHINE_AMD64,
  IMAGE_FILE_MACHINE_ARM64,
  IMAGE_FILE_MACHINE_ARM64EC,
  IMAGE_FILE_MACHINE_ARM64X,
  IMAGE_FILE_MACHINE_I386,
  getCanonicalPeMachine
} from "../machine.js";

const isArm64ExceptionMachine = (machine: number): boolean =>
  machine === IMAGE_FILE_MACHINE_ARM64 ||
  machine === IMAGE_FILE_MACHINE_ARM64EC ||
  machine === IMAGE_FILE_MACHINE_ARM64X;

export { createEmptyExceptionDirectory, type PeExceptionDirectory } from "./types.js";

export async function parseExceptionDirectory(
  reader: FileRangeReader,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  machine = IMAGE_FILE_MACHINE_AMD64,
  readyToRun?: PeClrReadyToRun | null
): Promise<PeExceptionDirectory | null> {
  const canonicalMachine = getCanonicalPeMachine(machine);
  if (canonicalMachine === IMAGE_FILE_MACHINE_I386) {
    const readyToRunException = await parseReadyToRunX86ExceptionDirectory(
      reader,
      dataDirs,
      rvaToOff,
      readyToRun
    );
    if (readyToRunException) return readyToRunException;
  }
  if (canonicalMachine === IMAGE_FILE_MACHINE_AMD64) {
    return parseAmd64ExceptionDirectory(reader, dataDirs, rvaToOff);
  }
  if (isArm64ExceptionMachine(canonicalMachine)) {
    return parseArm64ExceptionDirectory(reader, dataDirs, rvaToOff);
  }
  const dir = dataDirs.find(directory => directory.name === "EXCEPTION");
  if (!dir || (dir.rva === 0 && dir.size === 0)) {
    return null;
  }
  if (dir.rva === 0) {
    return createEmptyExceptionDirectory([
      "Exception directory has a non-zero size but RVA is 0."
    ]);
  }
  return createEmptyExceptionDirectory([
    `Exception directory decoding is not implemented for machine 0x${machine.toString(16)}.`
  ]);
}
