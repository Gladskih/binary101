"use strict";

import { readGuid } from "./utils.js";

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
  const iso = new Date(date).toISOString();
  if (year < 1980 || year > 2107) {
    return `${iso} (unusual timestamp — DOS date/time valid but out of normal range)`;
  }
  return iso;
};

const readAsciiZ = (bytes, offset) => {
  let end = offset;
  while (end < bytes.length && bytes[end] !== 0) end += 1;
  const raw = bytes.subarray(offset, end);
  let text = "";
  for (const b of raw) {
    if (b >= 0x20 && b <= 0x7e) text += String.fromCharCode(b);
  }
  return { text: text.trim() || null, bytesConsumed: (end - offset) + (end < bytes.length ? 1 : 0) };
};

const readAsciiNullTerminated = (bytes, offset) => {
  const { text } = readAsciiZ(bytes, offset);
  return text || "";
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
  if (!result) return "";
  if (result.length > 260) return "";
  if (/[\u0001-\u0008\u000b\u000c\u000e-\u001f]/.test(result)) return "";
  return result.trim();
};

const parseExtensionBlocks = (bytes, offset) => {
  const blocks = [];
  let cursor = offset;
  let longName = null;
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  while (cursor + 8 <= bytes.length) {
    const size = dv.getUint16(cursor, true);
    if (size === 0) break;
    if (size < 8 || size > bytes.length - cursor) break;
    const version = dv.getUint16(cursor + 2, true);
    const signature = dv.getUint32(cursor + 4, true) >>> 0;
    let blockLongName = null;

    if (signature === 0xbeef0004) {
      // File entry extension block (0xbeef0004) as documented by libfwsi.
      // Require a minimally sane size for this structure.
      if (size < 10) {
        blocks.push({ size, signature, longName: null, truncated: true });
        break;
      }

      let c2 = 8;
      // Creation + access times (8 bytes) for version >= 3
      if (size >= c2 + 8) c2 += 8;
      // Unknown 2 bytes
      if (size >= c2 + 2) c2 += 2;
      // If version >= 7: 2 + 8 + 8 of extra data
      if (version >= 7 && size >= c2 + 2 + 8 + 8) c2 += 2 + 8 + 8;

      // Long string size
      let longSize = 0;
      if (version >= 3 && size >= c2 + 2) {
        longSize = dv.getUint16(cursor + c2, true);
        c2 += 2;
      }

      // Version-specific padding
      if (version >= 9 && size >= c2 + 4) c2 += 4;
      if (version >= 8 && size >= c2 + 4) c2 += 4;

      const longStart = c2;
      const longEnd =
        longSize > 0 && longStart + longSize <= size ? longStart + longSize : size;
      if (longStart < size && longStart < longEnd) {
        const nameBytes = new Uint8Array(
          dv.buffer,
          dv.byteOffset + cursor + longStart,
          longEnd - longStart
        );
        blockLongName = readUtf16NullTerminated(nameBytes, 0) || null;
        if (blockLongName) longName = blockLongName;
      }
    }

    blocks.push({ size, signature, longName: blockLongName, truncated: false });
    cursor += size;
  }
  return { longName, blocks };
};

const parseFileEntry = bytes => {
  // File/folder shell items (type 0x31/0x32) with DOS date/time.
  if (!bytes || bytes.length < 12) return null;
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let offset = 2; // type + sortIndex
  const fileSize = dv.getUint32(offset, true);
  offset += 4;
  const dosDate = dv.getUint16(offset, true);
  offset += 2;
  const dosTime = dv.getUint16(offset, true);
  offset += 2;
  const attributes = dv.getUint16(offset, true);
  offset += 2;
  const { text: shortName, bytesConsumed } = readAsciiZ(bytes, offset);
  offset += bytesConsumed;

  // Primary name (shortName) is 16-bit aligned; for ASCII this can introduce
  // an extra zero byte so align to the next 2-byte boundary before extension blocks.
  if (offset % 2 !== 0 && offset < bytes.length) offset += 1;

  let longName = null;
  let extensionBlocks = [];
  if (offset + 8 <= bytes.length) {
    const extBytes = bytes.subarray(offset, bytes.length);
    ({ longName, blocks: extensionBlocks } = parseExtensionBlocks(extBytes, 0));
  }
  return {
    shortName: shortName || null,
    longName,
    fileSize,
    modified: dosDateTimeToIso(dosDate, dosTime),
    attributes,
    extensionBlocks
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
  const length = blockDv.byteLength >= 12 ? blockDv.getUint32(8, true) : null;
  const version = blockDv.byteLength >= 16 ? blockDv.getUint32(12, true) : null;
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
  const droidBirthVolume = blockDv.byteLength >= 48 ? readGuid(blockDv, 32) : null;
  const droidBirthObject = blockDv.byteLength >= 64 ? readGuid(blockDv, 48) : null;
  const droidVolume = blockDv.byteLength >= 80 ? readGuid(blockDv, 64) : null;
  const droidObject = blockDv.byteLength >= 96 ? readGuid(blockDv, 80) : null;
  return { length, version, machineId, droidVolume, droidObject, droidBirthVolume, droidBirthObject };
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
      return "Unknown shell item class";
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
      extensionBlocks: fileEntry?.extensionBlocks || [],
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
