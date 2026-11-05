"use strict";

import { hex, humanSize } from "../../binary-utils.js";

const SECTION_HINTS: Record<string, string> = {
  ".text": "Code (executable instructions)",
  ".rdata": "Read-only data (constants, import name table)",
  ".data": "Initialized writable data",
  ".bss": "Uninitialized data (zero-initialized at load)",
  ".rsrc": "Resource tree (icons, dialogs, manifests)",
  ".reloc": "Base relocations",
  ".tls": "Thread Local Storage",
  ".pdata": "Exception pdata (x64 unwind info)"
};

export const knownSectionName = (name: string): string | null => SECTION_HINTS[name.toLowerCase()] || null;

export const formatPointerHex = (value: bigint, width: number): string =>
  `0x${value.toString(16).padStart(width, "0")}`;

export const formatBigByteSize = (value: bigint): string => value <= BigInt(Number.MAX_SAFE_INTEGER)
  ? humanSize(Number(value))
  : `${value} bytes (0x${value.toString(16)})`;

export const formatWordListHex = (values: number[]): string =>
  values.map(value => hex(value >>> 0, 8)).join(", ");
