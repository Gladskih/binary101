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

export const linkerVersionHint = (major: number, minor: number): string => {
  const version = `${major}.${minor}`;
  const map: Record<string, string> = {
    "6.0": "VS6 (VC++ 6.0)",
    "7.0": "VS2002",
    "7.1": "VS2003",
    "8.0": "VS2005",
    "9.0": "VS2008",
    "10.0": "VS2010",
    "11.0": "VS2012",
    "12.0": "VS2013",
    "14.0": "VS2015 era",
    "14.1": "VS2017 era",
    "14.2": "VS2019 era",
    "14.3": "VS2022 era"
  };
  const hint =
    map[version] ||
    map[`${major}.0`] ||
    (major >= 14 ? "MSVC (VS2015+ era or lld-link)" : "MSVC (pre-VS2015)");
  return `${version} - ${hint}`;
};

export const winVersionName = (major: number, minor: number): string => {
  const key = `${major}.${minor}`;
  const names: Record<string, string> = {
    "5.1": "Windows XP",
    "5.2": "Windows Server 2003",
    "6.0": "Windows Vista",
    "6.1": "Windows 7",
    "6.2": "Windows 8",
    "6.3": "Windows 8.1",
    "10.0": "Windows 10+"
  };
  const label = names[key] || key;
  return `${label} (${key})`;
};
