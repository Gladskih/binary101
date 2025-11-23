"use strict";

import { readGuid, readNullTerminatedString, readFiletime } from "./utils.js";
import { parseTrackerData, parsePidlItems } from "./pidl.js";

const PROPERTY_KEY_LABELS = {
  "f29f85e0-4ff9-1068-ab91-08002b27b3d9:2": "System.Link.TargetParsingPath",
  "f29f85e0-4ff9-1068-ab91-08002b27b3d9:3": "System.Link.WorkingDirectory",
  "f29f85e0-4ff9-1068-ab91-08002b27b3d9:5": "System.Link.Arguments",
  "446d16b1-8dad-4870-a748-402ea43d788c:104": "System.VolumeId"
};

const PROPERTY_TYPE_NAMES = {
  0x0000: "Empty",
  0x0001: "Null",
  0x0002: "Signed 16-bit",
  0x0003: "Signed 32-bit",
  0x0004: "Float",
  0x0005: "Double",
  0x0006: "Currency",
  0x0007: "Date",
  0x0008: "BSTR",
  0x000b: "Boolean",
  0x0010: "Signed 8-bit",
  0x0011: "Unsigned 8-bit",
  0x0012: "Unsigned 16-bit",
  0x0013: "Unsigned 32-bit",
  0x0014: "Signed 64-bit",
  0x0015: "Unsigned 64-bit",
  0x001e: "ANSI string",
  0x001f: "Unicode string",
  0x0040: "Filetime",
  0x0041: "Blob",
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

const decodeVector = (dv, offset, available, baseType) => {
  if (available < 4) return { value: null, truncated: true };
  const count = dv.getUint32(offset, true);
  const values = [];
  let cursor = offset + 4;
  for (let i = 0; i < count && cursor < offset + available; i += 1) {
    const remaining = offset + available - cursor;
    let element = null;
    switch (baseType) {
      case 0x0011: // UI1
        element = dv.getUint8(cursor);
        cursor += 1;
        break;
      case 0x0010: // I1
        element = dv.getInt8(cursor);
        cursor += 1;
        break;
      case 0x0002: // I2
        if (remaining < 2) return { value: values, truncated: true };
        element = dv.getInt16(cursor, true);
        cursor += 2;
        break;
      case 0x0012: // UI2
        if (remaining < 2) return { value: values, truncated: true };
        element = dv.getUint16(cursor, true);
        cursor += 2;
        break;
      case 0x0003: // I4
        if (remaining < 4) return { value: values, truncated: true };
        element = dv.getInt32(cursor, true);
        cursor += 4;
        break;
      case 0x0013: // UI4
        if (remaining < 4) return { value: values, truncated: true };
        element = dv.getUint32(cursor, true);
        cursor += 4;
        break;
      case 0x0014: // I8
        if (remaining < 8 || typeof dv.getBigInt64 !== "function") {
          return { value: values, truncated: true };
        }
        element = dv.getBigInt64(cursor, true);
        cursor += 8;
        break;
      case 0x0015: // UI8
        if (remaining < 8 || typeof dv.getBigUint64 !== "function") {
          return { value: values, truncated: true };
        }
        element = dv.getBigUint64(cursor, true);
        cursor += 8;
        break;
      case 0x0048: // CLSID
        if (remaining < 16) return { value: values, truncated: true };
        element = readGuid(dv, cursor);
        cursor += 16;
        break;
      default:
        return { value: values, truncated: true };
    }
    values.push(element);
  }
  return { value: values, truncated: cursor > offset + available };
};

const parsePropertyValue = (dv, offset, declaredSize, warnings, label) => {
  if (declaredSize < 4 || offset + 4 > dv.byteLength) {
    return { type: null, typeName: null, value: null, truncated: true };
  }
  let type = dv.getUint16(offset, true);
  const rawType = type;
  const lowByte = rawType & 0xff;
  const highByte = (rawType >> 8) & 0xff;
  // Some property stores encode the VARTYPE in the high byte (e.g. 0x4800 for VT_CLSID).
  // If the low byte is zero and the high byte maps to a known type, normalise.
  if (lowByte === 0 && highByte !== 0 && propertyTypeName(highByte)) {
    type = highByte;
  }
  const padding = dv.getUint16(offset + 2, true); // reserved/padding
  const isVector = (type & 0x1000) !== 0;
  const baseType = isVector ? type & ~0x1000 : type;
  const dataStart = offset + 4;
  const declaredEnd = offset + declaredSize;
  const clampedEnd = Math.min(declaredEnd, dv.byteLength);
  const available = Math.max(0, clampedEnd - dataStart);
  const typeName = propertyTypeName(baseType);
  let value = null;
  let truncated = declaredEnd > dv.byteLength;

  const parseScalar = () => {
    switch (baseType) {
      case 0x001f:
        return parsePropertyString(dv, dataStart, available, true);
      case 0x001e:
        return parsePropertyString(dv, dataStart, available, false);
      case 0x0013:
        return available >= 4 ? dv.getUint32(dataStart, true) : null;
      case 0x0003:
        return available >= 4 ? dv.getInt32(dataStart, true) : null;
      case 0x000b:
        return available >= 2 ? dv.getInt16(dataStart, true) !== 0 : null;
      case 0x0014:
        return available >= 8 && typeof dv.getBigInt64 === "function"
          ? dv.getBigInt64(dataStart, true)
          : null;
      case 0x0015:
        return available >= 8 && typeof dv.getBigUint64 === "function"
          ? dv.getBigUint64(dataStart, true)
          : null;
      case 0x0040: {
        if (available >= 8) {
          const ftView = new DataView(dv.buffer, dv.byteOffset + dataStart, Math.min(8, available));
          return readFiletime(ftView, 0).iso;
        }
        return null;
      }
      case 0x0048: {
        if (available >= 16) {
          const guidView = new DataView(dv.buffer, dv.byteOffset + dataStart, Math.min(16, available));
          return readGuid(guidView, 0);
        }
        return null;
      }
      case 0x0041: {
        const bytes = new Uint8Array(
          dv.buffer,
          dv.byteOffset + dataStart,
          Math.max(0, Math.min(available, Math.max(0, declaredSize - 4)))
        );
        return { length: bytes.length };
      }
      default:
        return null;
    }
  };

  if (isVector) {
    const { value: vec, truncated: vecTrunc } = decodeVector(dv, dataStart, available, baseType);
    value = vec;
    truncated = truncated || vecTrunc;
  } else {
    value = parseScalar();
  }

  if (declaredEnd > dv.byteLength && warnings) {
    const labelText = label || "property store entry";
    warnings.push(`${labelText} value is truncated.`);
  }
  return { type, typeName, value, truncated, valueSize: declaredSize, isVector };
};

const parsePropertyStorage = (dv, warnings, formatId) => {
  const properties = [];
  let cursor = 0;
  const limit = dv.byteLength;
  while (cursor + 8 <= limit) {
    const valueSize = dv.getUint32(cursor, true);
    const propertyId = dv.getUint32(cursor + 4, true);
    if (valueSize === 0 && propertyId === 0) break;
    const valueOffset = cursor + 8;
    const valueEnd = valueOffset + valueSize;
    const step = Math.max(8, 8 + valueSize);
    const truncated = valueEnd > limit;
    const availableSize = Math.max(0, Math.min(valueSize, limit - valueOffset));
    const propertyValue = parsePropertyValue(
      new DataView(dv.buffer, dv.byteOffset),
      valueOffset,
      valueSize,
      warnings,
      `${formatId}:${propertyId}`
    );
    properties.push({
      id: propertyId,
      name: propertyKeyLabel(formatId, propertyId),
      ...propertyValue,
      truncated: propertyValue.truncated || truncated
    });
    cursor += step;
  }
  return { properties, endOffset: cursor };
};

const parsePropertyStore = (blockDv, warnings) => {
  const storages = [];
  const limit = blockDv.byteLength;
  let cursor = 8; // skip block header
  while (cursor + 24 <= limit) {
    const storageSize = blockDv.getUint32(cursor, true);
    if (storageSize === 0) break;
    if (storageSize < 24) {
      warnings.push("Property store storage is smaller than minimum header size.");
      break;
    }
    const magicValue = blockDv.getUint32(cursor + 4, true);
    let magic;
    if (magicValue === 0x53505331) {
      magic = "SPS1";
    } else if (magicValue === 0x53505332) {
      magic = "SPS2";
    } else {
      magic =
        String.fromCharCode(blockDv.getUint8(cursor + 4)) +
        String.fromCharCode(blockDv.getUint8(cursor + 5)) +
        String.fromCharCode(blockDv.getUint8(cursor + 6)) +
        String.fromCharCode(blockDv.getUint8(cursor + 7));
    }
    const formatId = readGuid(blockDv, cursor + 8);
    const storageStart = cursor + 24;
    const storageEnd = cursor + storageSize;
    const truncated = storageEnd > limit;
    const storageView = new DataView(
      blockDv.buffer,
      blockDv.byteOffset + storageStart,
      Math.max(0, limit - storageStart)
    );
    const { properties } = parsePropertyStorage(storageView, warnings, formatId);
    storages.push({
      formatId,
      size: storageSize,
      magic,
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
