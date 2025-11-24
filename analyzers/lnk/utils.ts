// @ts-nocheck
"use strict";

const FILETIME_TICKS_PER_MS = 10000n;
const FILETIME_EPOCH_BIAS_MS = 11644473600000n;
const UTF16_DECODER = new TextDecoder("utf-16le", { fatal: false });

export const SHELL_LINK_HEADER_SIZE = 0x4c;
export const SHELL_LINK_CLSID = "00021401-0000-0000-c000-000000000046";

export const linkFlag = (flags, mask) => (flags & mask) !== 0;

export const driveTypeName = driveType => {
  switch (driveType) {
    case 0:
      return "Unknown";
    case 1:
      return "No root directory";
    case 2:
      return "Removable drive";
    case 3:
      return "Fixed drive";
    case 4:
      return "Network drive";
    case 5:
      return "CD-ROM";
    case 6:
      return "RAM disk";
    default:
      return null;
  }
};

export const providerTypeName = value => {
  switch (value) {
    case 0x001a0000:
      return "NetWare";
    case 0x001b0000:
      return "Vines";
    case 0x001c0000:
      return "MSNet";
    case 0x001f0000:
      return "VMNet";
    case 0x00200000:
      return "NetCray";
    case 0x00210000:
      return "CEF";
    case 0x00220000:
      return "SFS";
    case 0x002a0000:
      return "SMB (LanMan)";
    case 0x002b0000:
      return "DFS / WebDAV";
    case 0x00300000:
      return "NFS";
    default:
      return null;
  }
};

const hotKeyName = vk => {
  if (vk >= 0x41 && vk <= 0x5a) return String.fromCharCode(vk);
  if (vk >= 0x30 && vk <= 0x39) return String.fromCharCode(vk);
  if (vk >= 0x70 && vk <= 0x87) return `F${vk - 0x6f}`;
  const map = {
    0x08: "Backspace",
    0x09: "Tab",
    0x0d: "Enter",
    0x1b: "Esc",
    0x20: "Space",
    0x21: "PgUp",
    0x22: "PgDn",
    0x23: "End",
    0x24: "Home",
    0x25: "Left",
    0x26: "Up",
    0x27: "Right",
    0x28: "Down",
    0x2d: "Insert",
    0x2e: "Delete"
  };
  return map[vk] || null;
};

export const describeHotKey = value => {
  if (!value) return null;
  const key = value & 0xff;
  const modifiers = value >> 8;
  const parts = [];
  if (modifiers & 0x01) parts.push("Shift");
  if (modifiers & 0x02) parts.push("Ctrl");
  if (modifiers & 0x04) parts.push("Alt");
  const keyLabel = hotKeyName(key) || `VK-${key.toString(16).padStart(2, "0")}`;
  parts.push(keyLabel);
  return parts.join("+");
};

export const showCommandName = value => {
  switch (value) {
    case 1:
      return "Normal window";
    case 3:
      return "Maximized";
    case 7:
      return "Minimized";
    default:
      return null;
  }
};

export const readGuid = (dv, offset) => {
  if (offset + 16 > dv.byteLength) return null;
  const data1 = dv.getUint32(offset, true).toString(16).padStart(8, "0");
  const data2 = dv.getUint16(offset + 4, true).toString(16).padStart(4, "0");
  const data3 = dv.getUint16(offset + 6, true).toString(16).padStart(4, "0");
  const b = [];
  for (let i = 0; i < 8; i += 1) {
    b.push(dv.getUint8(offset + 8 + i).toString(16).padStart(2, "0"));
  }
  return `${data1}-${data2}-${data3}-${b.slice(0, 2).join("")}-${b.slice(2).join("")}`.toLowerCase();
};

const decodeAnsi = bytes => {
  let out = "";
  for (let i = 0; i < bytes.length; i += 1) {
    const code = bytes[i];
    if (code === 0) break;
    out += String.fromCharCode(code);
  }
  return out;
};

export const readFiletime = (dv, offset) => {
  if (offset + 8 > dv.byteLength || typeof dv.getBigUint64 !== "function") {
    return { raw: null, iso: null };
  }
  const raw = dv.getBigUint64(offset, true);
  if (raw === 0n) return { raw, iso: null };
  const ms = raw / FILETIME_TICKS_PER_MS - FILETIME_EPOCH_BIAS_MS;
  const msNumber = Number(ms);
  if (!Number.isFinite(msNumber)) return { raw, iso: null };
  const date = new Date(msNumber);
  const iso = date.toISOString();
  const year = date.getUTCFullYear();
  const taggedIso = year < 1980 || year > 2200 ? `${iso} (unusual)` : iso;
  return { raw, iso: taggedIso };
};

export const readNullTerminatedString = (dv, offset, maxEnd, isUnicode) => {
  const limit = Math.min(maxEnd, dv.byteLength);
  if (offset >= limit) return "";
  if (isUnicode) {
    const codes = [];
    for (let i = offset; i + 1 < limit; i += 2) {
      const code = dv.getUint16(i, true);
      if (code === 0) break;
      codes.push(code);
    }
    return String.fromCharCode(...codes);
  }
  const bytes = [];
  for (let i = offset; i < limit; i += 1) {
    const code = dv.getUint8(i);
    if (code === 0) break;
    bytes.push(code);
  }
  return decodeAnsi(bytes);
};

export const readCountedString = (dv, offset, isUnicode, warnings, label) => {
  if (offset + 2 > dv.byteLength) {
    warnings.push(`${label} length is truncated`);
    return { value: null, size: dv.byteLength - offset };
  }
  const charCount = dv.getUint16(offset, true);
  const charSize = isUnicode ? 2 : 1;
  const byteLength = charCount * charSize;
  const start = offset + 2;
  const end = start + byteLength;
  if (end > dv.byteLength) {
    warnings.push(`${label} content is truncated`);
    return { value: null, size: dv.byteLength - offset };
  }
  const bytes = new Uint8Array(dv.buffer, dv.byteOffset + start, byteLength);
  const value = isUnicode ? UTF16_DECODER.decode(bytes) : decodeAnsi(bytes);
  const trimmed = value.replace(/\0+$/, "");
  return { value: trimmed, size: byteLength + 2 };
};
