"use strict";

import { readGuid, readFiletime } from "./utils.js";

const dosDateTimeToIso = (dosDate, dosTime) => {
  const day = dosDate & 0x1f;
  const month = (dosDate >> 5) & 0x0f;
  const year = ((dosDate >> 9) & 0x7f) + 1980;
  const seconds = (dosTime & 0x1f) * 2;
  const minutes = (dosTime >> 5) & 0x3f;
  const hours = (dosTime >> 11) & 0x1f;
  if (day === 0 || month === 0) return null;
  const date = Date.UTC(year, month - 1, day, hours, minutes, seconds);
  if (!Number.isFinite(date)) return null;
  return new Date(date).toISOString();
};

const readAsciiNullTerminated = (bytes, offset) => {
  let out = "";
  for (let i = offset; i < bytes.length; i += 1) {
    const b = bytes[i];
    if (b === 0) break;
    if (b >= 0x20 && b <= 0x7e) out += String.fromCharCode(b);
  }
  return out.trim();
};

const readUtf16NullTerminated = (bytes, offset) => {
  if (offset >= bytes.length - 1) return "";
  const length = bytes.length - offset;
  if (length < 4 || length % 2 !== 0) return "";
  const dv = new DataView(bytes.buffer, bytes.byteOffset + offset, length);
  let result = "";
  for (let i = 0; i + 1 < dv.byteLength; i += 2) {
    const code = dv.getUint16(i, true);
    if (code === 0) break;
    result += String.fromCharCode(code);
  }
  // Require mostly printable characters to avoid garbage.
  const printable = [...result].filter(ch => {
    const c = ch.charCodeAt(0);
    return c >= 0x20 && c <= 0x7e;
  }).length;
  if (!result || printable * 2 < result.length) return "";
  return result.trim();
};

const parseFileEntryExtension = (dv, offset) => {
  if (offset + 8 > dv.byteLength) return { longName: null };
  const size = dv.getUint16(offset, true);
  const end = offset + size;
  if (size < 0x12 || end > dv.byteLength) {
    return { longName: null, truncated: true };
  }
  const signature = dv.getUint32(offset + 4, true);
  if ((signature >>> 16) !== 0xbeef) return { longName: null };
  const creation = readFiletime(dv, offset + 8);
  const access = readFiletime(dv, offset + 16);
  const nameStart = offset + 0x12;
  const nameBytes = new Uint8Array(
    dv.buffer,
    dv.byteOffset + nameStart,
    Math.max(0, end - nameStart)
  );
  const longName = readUtf16NullTerminated(nameBytes, 0) || null;
  return {
    longName,
    created: creation?.iso || null,
    accessed: access?.iso || null
  };
};

const parseFileEntry = bytes => {
  // File/folder shell items (type 0x31/0x32) with DOS date/time.
  if (!bytes || bytes.length < 12) return null;
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let offset = 2; // skip type + sort index (u8 each)
  const fileSize = dv.getUint32(offset, true);
  offset += 4;
  const dosDate = dv.getUint16(offset, true);
  offset += 2;
  const dosTime = dv.getUint16(offset, true);
  offset += 2;
  const attributes = dv.getUint16(offset, true);
  offset += 2;
  const shortName = readAsciiNullTerminated(bytes, offset);
  offset += shortName.length + 1;
  if (offset % 2 !== 0) offset += 1;
  const extension = parseFileEntryExtension(dv, offset);
  const longName = extension.longName || null;
  return {
    shortName: shortName || null,
    longName,
    fileSize,
    modified: dosDateTimeToIso(dosDate, dosTime),
    attributes
  };
};

const parseDriveItem = bytes => {
  if (!bytes || bytes.length < 2) return null;
  // Drive shell items store the drive label as an ANSI string after a small header.
  const labelOffsets = [1, 2, 3];
  for (const off of labelOffsets) {
    const label = readAsciiNullTerminated(bytes, off);
    if (label) return { shortName: label, longName: null };
  }
  return null;
};

export const parseTrackerData = blockDv => {
  if (blockDv.byteLength < 64) return null;
  const length = blockDv.getUint32(8, true);
  const version = blockDv.getUint32(12, true);
  const machineBytes = new Uint8Array(
    blockDv.buffer,
    blockDv.byteOffset + 16,
    Math.min(16, blockDv.byteLength - 16)
  );
  let machineId = "";
  for (const b of machineBytes) {
    if (b === 0) break;
    if (b >= 0x20 && b <= 0x7e) machineId += String.fromCharCode(b);
  }
  if (!machineId) machineId = null;
  const droid = blockDv.byteLength >= 48 ? readGuid(blockDv, 32) : null;
  const droidBirth = blockDv.byteLength >= 64 ? readGuid(blockDv, 48) : null;
  return { length, version, machineId, droid, droidBirth };
};

const typeNameFromByte = value => {
  switch (value) {
    case 0x1f:
      return "Root";
    case 0x2f:
      return "Drive";
    case 0x31:
      return "Folder";
    case 0x32:
      return "File";
    default:
      return null;
  }
};

export const parsePidlItems = (dv, start, end, warnings) => {
  const items = [];
  let cursor = start;
  while (cursor + 2 <= end && cursor + 2 <= dv.byteLength) {
    const size = dv.getUint16(cursor, true);
    if (size === 0) break; // terminator
    if (size < 2) {
      warnings.push("Encountered malformed IDList item with size < 2.");
      break;
    }
    const itemEnd = cursor + size;
    const truncated = itemEnd > end || itemEnd > dv.byteLength;
    const bodyStart = cursor + 2;
    const bodyEnd = truncated ? Math.min(itemEnd, Math.min(end, dv.byteLength)) : itemEnd;
    const body = new Uint8Array(
      dv.buffer,
      dv.byteOffset + bodyStart,
      Math.max(0, bodyEnd - bodyStart)
    );
    const typeByte = body.length ? body[0] : null;
    const typeName = typeNameFromByte(typeByte);
    const fileEntry =
      typeName === "Folder" || typeName === "File"
        ? parseFileEntry(body)
        : typeName === "Drive"
          ? parseDriveItem(body)
          : null;
    let clsid = null;
    if (typeName === "Root" && body.length >= 17) {
      clsid = readGuid(new DataView(body.buffer, body.byteOffset, body.byteLength), 1);
    }
    items.push({
      index: items.length,
      size,
      typeByte,
      typeName,
      typeHex: typeByte != null ? `0x${typeByte.toString(16).padStart(2, "0")}` : null,
      fileSize: fileEntry?.fileSize ?? null,
      modified: fileEntry?.modified || null,
      attributes: fileEntry?.attributes ?? null,
      shortName: fileEntry?.shortName || null,
      longName: fileEntry?.longName || null,
      clsid,
      truncated
    });
    if (truncated) break;
    cursor = itemEnd;
  }
  const terminatorPresent =
    cursor + 2 <= end && cursor + 2 <= dv.byteLength && dv.getUint16(cursor, true) === 0;
  return { items, endOffset: cursor, terminatorPresent };
};
