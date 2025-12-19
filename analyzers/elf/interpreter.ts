"use strict";

import { readAsciiString } from "../../binary-utils.js";
import type { ElfInterpreterInfo, ElfProgramHeader } from "./types.js";

const PT_INTERP = 3;

const toSafeIndex = (value: bigint, label: string, issues: string[]): number | null => {
  const num = Number(value);
  if (!Number.isSafeInteger(num) || num < 0) {
    issues.push(`${label} (${value.toString()}) is too large to index into the file.`);
    return null;
  }
  return num;
};

export async function parseElfInterpreter(
  file: File,
  programHeaders: ElfProgramHeader[]
): Promise<ElfInterpreterInfo | null> {
  const issues: string[] = [];
  const interp = programHeaders.find(ph => ph.type === PT_INTERP && ph.filesz > 0n);
  if (!interp) return null;

  const start = toSafeIndex(interp.offset, "PT_INTERP offset", issues);
  const size = toSafeIndex(interp.filesz, "PT_INTERP size", issues);
  if (start == null || size == null || size <= 0) return { path: "", issues };

  const end = Math.min(file.size, start + size);
  if (start >= file.size || end <= start) {
    issues.push("PT_INTERP falls outside the file.");
    return { path: "", issues };
  }
  if (end !== start + size) {
    issues.push("PT_INTERP is truncated.");
  }
  const bytes = new Uint8Array(await file.slice(start, end).arrayBuffer());
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const path = readAsciiString(dv, 0, dv.byteLength);
  return { path, issues };
}
