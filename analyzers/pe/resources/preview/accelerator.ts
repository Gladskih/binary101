"use strict";

import type {
  ResourceAcceleratorEntryPreview,
  ResourcePreviewResult
} from "./types.js";

// ACCELTABLEENTRY.fFlags bits. Sources:
// Microsoft Learn, ACCELTABLEENTRY / https://learn.microsoft.com/en-us/windows/win32/menurc/acceltableentry
// Virtual-Key Codes / https://learn.microsoft.com/en-us/windows/win32/inputdev/virtual-key-codes
const FVIRTKEY = 0x01;
const FNOINVERT = 0x02;
const FSHIFT = 0x04;
const FCONTROL = 0x08;
const FALT = 0x10;
const FLAST = 0x80;

const formatVirtualKey = (key: number): string => {
  // VK_F1..VK_F24 occupy 0x70..0x87 in the Win32 virtual-key table.
  if (key >= 0x70 && key <= 0x87) return `F${key - 0x6f}`;
  // ASCII digits and uppercase Latin letters share the same values as their virtual-key codes.
  if (key >= 0x30 && key <= 0x39) return String.fromCharCode(key);
  if (key >= 0x41 && key <= 0x5a) return String.fromCharCode(key);
  const names = new Map<number, string>([
    [0x08, "Backspace"],
    [0x09, "Tab"],
    [0x0d, "Enter"],
    [0x1b, "Esc"],
    [0x20, "Space"],
    [0x25, "Left"],
    [0x26, "Up"],
    [0x27, "Right"],
    [0x28, "Down"],
    [0x2d, "Insert"],
    [0x2e, "Delete"]
  ]);
  return names.get(key) || `VK_0x${key.toString(16).padStart(2, "0")}`;
};

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

const parseAcceleratorEntries = (view: DataView): ResourceAcceleratorEntryPreview[] => {
  const entries: ResourceAcceleratorEntryPreview[] = [];
  // ACCELTABLEENTRY is DWORD-aligned in the resource format (8 bytes); keep a 6-byte fallback
  // for resilience when malformed data omits the trailing padding word.
  const recordSize = view.byteLength % 8 === 0 ? 8 : 6;
  for (let offset = 0; offset + recordSize <= view.byteLength; offset += recordSize) {
    const flags = view.getUint8(offset);
    const key = view.getUint16(offset + 2, true);
    const id = view.getUint16(offset + 4, true);
    entries.push({
      id,
      key: formatAcceleratorKey(flags, key),
      modifiers: describeAcceleratorFlags(flags).filter(flag => flag === "Shift" || flag === "Ctrl" || flag === "Alt"),
      flags: describeAcceleratorFlags(flags)
    });
    if ((flags & FLAST) !== 0) break;
  }
  return entries;
};

export const addAcceleratorPreview = (
  data: Uint8Array,
  typeName: string
): ResourcePreviewResult | null => {
  if (typeName !== "ACCELERATOR" || data.byteLength < 6) return null;
  const entries = parseAcceleratorEntries(new DataView(data.buffer, data.byteOffset, data.byteLength));
  if (!entries.length) {
    return { issues: ["ACCELERATOR resource is truncated or malformed."] };
  }
  return {
    preview: {
      previewKind: "accelerator",
      acceleratorPreview: { entries }
    }
  };
};
