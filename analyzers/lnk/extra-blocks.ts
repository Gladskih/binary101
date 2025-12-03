"use strict";

import { readGuid, readNullTerminatedString } from "./utils.js";
import { parseTrackerData, parsePidlItems } from "./pidl.js";
import { parsePropertyStore } from "./property-store.js";
import type {
  LnkEnvironmentStrings,
  LnkKnownFolderData,
  LnkPropertyStoreData,
  LnkSpecialFolderData,
  LnkVistaIdListData
} from "./types.js";

const nameForExtraBlock = (signature: number): string | null => {
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

const parseKnownFolderBlock = (blockDv: DataView): LnkKnownFolderData | null => {
  if (blockDv.byteLength < 0x1c) return null;
  const guid = readGuid(blockDv, 8);
  const offset = blockDv.getUint32(0x18, true);
  return { knownFolderId: guid, offset };
};

const parseSpecialFolderBlock = (blockDv: DataView): LnkSpecialFolderData | null => {
  if (blockDv.byteLength < 0x10) return null;
  const folderId = blockDv.getUint32(8, true);
  const offset = blockDv.getUint32(12, true);
  return { folderId, offset };
};

const parseConsoleFeBlock = (blockDv: DataView): { codePage: number } | null => {
  if (blockDv.byteLength < 0x0c) return null;
  return { codePage: blockDv.getUint16(8, true) };
};

const parseFixedStringBlock = (blockDv: DataView): LnkEnvironmentStrings => {
  const ansi = readNullTerminatedString(blockDv, 8, Math.min(blockDv.byteLength, 8 + 260), false);
  const unicode = readNullTerminatedString(
    blockDv,
    8 + 260,
    Math.min(blockDv.byteLength, 8 + 260 + 520),
    true
  );
  return { ansi: ansi || null, unicode: unicode || null };
};

const parseVistaIdList = (blockDv: DataView, warnings: string[]): LnkVistaIdListData => {
  if (blockDv.byteLength <= 8) return { items: [], terminatorPresent: false };
  const { items, terminatorPresent } = parsePidlItems(blockDv, 8, blockDv.byteLength, warnings);
  return { items, terminatorPresent };
};

const parseExtraBlock = (signature: number, blockDv: DataView, warnings: string[]): unknown => {
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
      return parsePropertyStore(blockDv, warnings) as LnkPropertyStoreData;
    case 0xa000000c:
      return parseVistaIdList(blockDv, warnings);
    default:
      return null;
  }
};

export { nameForExtraBlock, parseExtraBlock };
