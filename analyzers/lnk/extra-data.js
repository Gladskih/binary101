"use strict";

import { readGuid, readNullTerminatedString, readFiletime } from "./utils.js";
import { parseTrackerData, parsePidlItems } from "./pidl.js";

const PROPERTY_KEY_LABELS = {
  "f29f85e0-4ff9-1068-ab91-08002b27b3d9:2": "System.Link.TargetParsingPath",
  "f29f85e0-4ff9-1068-ab91-08002b27b3d9:3": "System.Link.WorkingDirectory",
  "f29f85e0-4ff9-1068-ab91-08002b27b3d9:5": "System.Link.Arguments"
};

const PROPERTY_TYPE_NAMES = {
  0x0000: "Empty",
  0x0001: "Null",
  0x0003: "Signed 32-bit",
  0x000b: "Boolean",
  0x0013: "Unsigned 32-bit",
  0x0014: "Signed 64-bit",
  0x0015: "Unsigned 64-bit",
  0x001e: "ANSI string",
  0x001f: "Unicode string",
  0x0040: "Filetime",
  0x0048: "CLSID"
};

const ansiFromBytes = bytes => {
  let out = "";
  for (let i = 0; i < bytes.length; i += 1) {
    const code = bytes[i];
    if (code === 0) break;
    out += String.fromCharCode(code);
  }
  return out;
};

const nameForExtraBlock = signature => {
  switch (signature >>> 0) {
    case 0xa0000001:
      return "Environment variables";
    case 0xa0000002:
      return "Console properties";
    case 0xa0000003:
      return "Tracker data";
    case 0xa0000004:
      return "Console code page";
    case 0xa0000005:
      return "Special folder";
    case 0xa0000006:
      return "Darwin data";
    case 0xa0000007:
      return "Icon environment";
    case 0xa0000008:
      return "Shim data";
    case 0xa0000009:
      return "Property store";
    case 0xa000000b:
      return "Known folder";
    case 0xa000000c:
      return "Vista+ IDList";
    default:
      return null;
  }
};

const parseFixedStringBlock = blockDv => {
  const ansi = readNullTerminatedString(blockDv, 8, Math.min(blockDv.byteLength, 8 + 260), false);
  const unicode = readNullTerminatedString(
    blockDv,
    8 + 260,
    Math.min(blockDv.byteLength, 8 + 260 + 520),
    true
  );
  return { ansi: ansi || null, unicode: unicode || null };
};

const parseKnownFolderBlock = blockDv => {
  if (blockDv.byteLength < 0x1c) return null;
  const guid = readGuid(blockDv, 8);
  const offset = blockDv.getUint32(0x18, true);
  return { knownFolderId: guid, offset };
};

const parseSpecialFolderBlock = blockDv => {
  if (blockDv.byteLength < 0x10) return null;
  const folderId = blockDv.getUint32(8, true);
  const offset = blockDv.getUint32(12, true);
  return { folderId, offset };
};

const parseConsoleFeBlock = blockDv => {
  if (blockDv.byteLength < 0x0c) return null;
  return { codePage: blockDv.getUint16(8, true) };
};

const propertyKeyLabel = (formatId, propertyId) => PROPERTY_KEY_LABELS[`${formatId}:${propertyId}`] || null;

const propertyTypeName = type => PROPERTY_TYPE_NAMES[type] || null;

const parsePropertyString = (dv, offset, available, isUnicode) => {
  if (available < 4) return null;
  const count = dv.getUint32(offset, true);
  if (count <= 0) return "";
  const maxBytes = available - 4;
  const byteLength = isUnicode ? Math.min(maxBytes, count * 2) : Math.min(maxBytes, count);
  const bytes = new Uint8Array(dv.buffer, dv.byteOffset + offset + 4, Math.max(0, byteLength));
  if (!bytes.length) return "";
  if (isUnicode) {
    let result = "";
    for (let i = 0; i + 1 < bytes.length; i += 2) {
      const code = bytes[i] | (bytes[i + 1] << 8);
      if (code === 0) break;
      result += String.fromCharCode(code);
    }
    return result.replace(/\0+$/, "");
  }
  return ansiFromBytes(bytes).replace(/\0+$/, "");
};

const parsePropertyValue = (dv, offset, valueSize, warnings, label) => {
  if (valueSize < 4 || offset + 4 > dv.byteLength) {
    return { type: null, typeName: null, value: null, truncated: offset + valueSize > dv.byteLength };
  }
  const type = dv.getUint32(offset, true);
  const dataStart = offset + 4;
  const valueEnd = offset + valueSize;
  const clampedEnd = Math.min(valueEnd, dv.byteLength);
  const available = Math.max(0, clampedEnd - dataStart);
  const typeName = propertyTypeName(type);
  let value = null;
  switch (type) {
    case 0x001f: {
      value = parsePropertyString(dv, dataStart, available, true);
      break;
    }
    case 0x001e: {
      value = parsePropertyString(dv, dataStart, available, false);
      break;
    }
    case 0x0013: {
      if (available >= 4) value = dv.getUint32(dataStart, true);
      break;
    }
    case 0x0003: {
      if (available >= 4) value = dv.getInt32(dataStart, true);
      break;
    }
    case 0x000b: {
      if (available >= 2) value = dv.getInt16(dataStart, true) !== 0;
      break;
    }
    case 0x0014: {
      if (available >= 8 && typeof dv.getBigInt64 === "function") {
        value = dv.getBigInt64(dataStart, true);
      }
      break;
    }
    case 0x0015: {
      if (available >= 8 && typeof dv.getBigUint64 === "function") {
        value = dv.getBigUint64(dataStart, true);
      }
      break;
    }
    case 0x0040: {
      if (available >= 8) {
        const ftView = new DataView(dv.buffer, dv.byteOffset + dataStart, Math.min(8, available));
        value = readFiletime(ftView, 0).iso;
      }
      break;
    }
    case 0x0048: {
      if (available >= 16) {
        const guidView = new DataView(dv.buffer, dv.byteOffset + dataStart, Math.min(16, available));
        value = readGuid(guidView, 0);
      }
      break;
    }
    default:
      break;
  }
  if (valueEnd > dv.byteLength && warnings) {
    const labelText = label || "property store entry";
    warnings.push(`${labelText} value is truncated.`);
  }
  return { type, typeName, value, truncated: valueEnd > dv.byteLength, valueSize };
};

const parsePropertyStorage = (dv, warnings, formatId) => {
  const properties = [];
  let cursor = 0;
  const limit = dv.byteLength;
  while (cursor + 8 <= limit) {
    const propertyId = dv.getUint32(cursor, true);
    const valueSize = dv.getUint32(cursor + 4, true);
    if (propertyId === 0 && valueSize === 0) break;
    const valueOffset = cursor + 8;
    const valueEnd = valueOffset + valueSize;
    const step = Math.max(8, valueSize + 8);
    if (valueSize === 0) {
      warnings.push(`Property ${propertyId} in ${formatId || "property store"} has zero length.`);
    }
    if (valueEnd > limit && warnings) {
      warnings.push(`Property ${propertyId} in ${formatId || "property store"} is truncated.`);
    }
    const propertyValue = parsePropertyValue(dv, valueOffset, valueSize, warnings, `${formatId}:${propertyId}`);
    properties.push({
      id: propertyId,
      name: propertyKeyLabel(formatId, propertyId),
      ...propertyValue
    });
    cursor += step;
    if (step === 8 && valueSize === 0) break;
  }
  return { properties, endOffset: cursor };
};

const parsePropertyStore = (blockDv, warnings) => {
  const storages = [];
  const limit = blockDv.byteLength;
  let cursor = 8; // skip block header
  while (cursor + 20 <= limit) {
    const formatId = readGuid(blockDv, cursor);
    const storageSize = blockDv.getUint32(cursor + 16, true);
    const storageStart = cursor + 20;
    const storageEnd = storageStart + storageSize;
    const truncated = storageEnd > limit;
    const storageView = new DataView(
      blockDv.buffer,
      blockDv.byteOffset + storageStart,
      Math.max(0, Math.min(storageEnd, limit) - storageStart)
    );
    const { properties } = parsePropertyStorage(storageView, warnings, formatId);
    storages.push({
      formatId,
      size: storageSize,
      truncated,
      properties
    });
    if (storageSize === 0) break;
    cursor = storageEnd;
  }
  return { storages };
};

const parseVistaIdList = (blockDv, warnings) => {
  if (blockDv.byteLength <= 8) return { items: [], terminatorPresent: false, truncated: true };
  const { items, terminatorPresent } = parsePidlItems(blockDv, 8, blockDv.byteLength, warnings);
  return { items, terminatorPresent };
};

const parseExtraBlock = (signature, blockDv, warnings) => {
  switch (signature >>> 0) {
    case 0xa0000001:
    case 0xa0000006:
    case 0xa0000007:
      return parseFixedStringBlock(blockDv);
    case 0xa0000004:
      return parseConsoleFeBlock(blockDv);
    case 0xa0000005:
      return parseSpecialFolderBlock(blockDv);
    case 0xa000000b:
      return parseKnownFolderBlock(blockDv);
    case 0xa0000003:
      return parseTrackerData(blockDv);
    case 0xa0000009:
      return parsePropertyStore(blockDv, warnings);
    case 0xa000000c:
      return parseVistaIdList(blockDv, warnings);
    default:
      return null;
  }
};

export const parseExtraData = (dv, offset, warnings) => {
  const blocks = [];
  let cursor = offset;
  let terminatorPresent = false;
  while (cursor + 4 <= dv.byteLength) {
    const size = dv.getUint32(cursor, true);
    if (size === 0) {
      terminatorPresent = true;
      break;
    }
    if (size < 8) {
      warnings.push("Encountered malformed ExtraData block smaller than header size.");
      break;
    }
    const signature = dv.getUint32(cursor + 4, true);
    const blockEnd = cursor + size;
    const clampedEnd = Math.min(blockEnd, dv.byteLength);
    const blockDv = new DataView(dv.buffer, dv.byteOffset + cursor, clampedEnd - cursor);
    blocks.push({
      size,
      signature,
      name: nameForExtraBlock(signature),
      truncated: blockEnd > dv.byteLength,
      parsed: parseExtraBlock(signature, blockDv, warnings)
    });
    if (blockEnd > dv.byteLength) break;
    cursor = blockEnd;
  }
  if (!terminatorPresent) {
    warnings.push("ExtraData section is missing the required terminal block.");
  }
  return { blocks, endOffset: cursor };
};
