"use strict";

import type {
  ResourceAcceleratorEntryPreview,
  ResourcePreviewResult
} from "./types.js";
import { formatVirtualKey } from "./virtual-key.js";

// ACCELTABLEENTRY.fFlags bits. Sources:
// Microsoft Learn, ACCELTABLEENTRY / https://learn.microsoft.com/en-us/windows/win32/menurc/acceltableentry
// Virtual-Key Codes / https://learn.microsoft.com/en-us/windows/win32/inputdev/virtual-key-codes
const FVIRTKEY = 0x01;
const FNOINVERT = 0x02;
const FSHIFT = 0x04;
const FCONTROL = 0x08;
const FALT = 0x10;
const FLAST = 0x80;

const formatAcceleratorKey = (flags: number, key: number): string =>
  (flags & FVIRTKEY) !== 0 ? formatVirtualKey(key) : String.fromCharCode(key & 0xff);

const describeAcceleratorFlags = (flags: number): string[] => {
  const out: string[] = [];
  if ((flags & FSHIFT) !== 0) out.push("Shift");
  if ((flags & FCONTROL) !== 0) out.push("Ctrl");
  if ((flags & FALT) !== 0) out.push("Alt");
  if ((flags & FVIRTKEY) !== 0) out.push("VirtualKey");
  if ((flags & FNOINVERT) !== 0) out.push("NoInvert");
  return out;
};

const parseAcceleratorEntries = (view: DataView, issues: string[]): ResourceAcceleratorEntryPreview[] => {
  const entries: ResourceAcceleratorEntryPreview[] = [];
  // ACCELTABLEENTRY always has an eight-byte stride. Recover a final six-byte prefix
  // without changing the stride of earlier entries. Source: ACCELTABLEENTRY, cited above.
  for (let offset = 0; offset + 6 <= view.byteLength; offset += 8) {
    const flags = view.getUint16(offset, true);
    const key = view.getUint16(offset + 2, true);
    const id = view.getUint16(offset + 4, true);
    const described = describeAcceleratorFlags(flags);
    if (flags & ~0x9f) issues.push("ACCELERATOR entry contains unknown flag bits.");
    if (offset + 8 > view.byteLength) issues.push("ACCELERATOR final entry padding is truncated.");
    entries.push({
      id,
      key: formatAcceleratorKey(flags, key),
      modifiers: described.filter(flag => flag === "Shift" || flag === "Ctrl" || flag === "Alt"),
      flags: described
    });
    if ((flags & FLAST) !== 0) return entries;
  }
  issues.push("ACCELERATOR table is truncated or lacks a final-entry marker.");
  return entries;
};

export const addAcceleratorPreview = (
  data: Uint8Array,
  typeName: string
): ResourcePreviewResult | null => {
  if (typeName !== "ACCELERATOR") return null;
  const issues: string[] = [];
  const entries = parseAcceleratorEntries(new DataView(data.buffer, data.byteOffset, data.byteLength), issues);
  if (!entries.length) {
    return { issues: ["ACCELERATOR resource is truncated or malformed."] };
  }
  return {
    preview: {
      previewKind: "accelerator",
      acceleratorPreview: { entries }
    },
    ...(issues.length ? { issues } : {})
  };
};
