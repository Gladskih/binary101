"use strict";

import { readGuid, readNullTerminatedString } from "./utils.js";

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

const parseExtraBlock = (signature, blockDv) => {
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
    default:
      return null;
  }
};

export const parseExtraData = (dv, offset, warnings) => {
  const blocks = [];
  let cursor = offset;
  while (cursor + 4 <= dv.byteLength) {
    const size = dv.getUint32(cursor, true);
    if (size === 0) break;
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
      parsed: parseExtraBlock(signature, blockDv)
    });
    if (blockEnd > dv.byteLength) break;
    cursor = blockEnd;
  }
  return { blocks, endOffset: cursor };
};
