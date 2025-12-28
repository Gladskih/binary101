"use strict";

import { toHex32 } from "../../binary-utils.js";
import type { Iso9660PathTable, Iso9660PathTableEntry, Iso9660StringEncoding } from "./types.js";
import { decodeStringField, readUint16Le, readUint32Le } from "./iso-parsing.js";

const formatOffsetHex = (offset: number): string => toHex32(offset >>> 0, 8);

export const parseTypeLPathTable = (opts: {
  bytes: Uint8Array;
  absoluteBaseOffset: number;
  encoding: Iso9660StringEncoding;
  pushIssue: (message: string) => void;
  maxEntries: number;
}): Pick<Iso9660PathTable, "entryCount" | "entries" | "omittedEntries"> => {
  const { bytes, absoluteBaseOffset, encoding, pushIssue, maxEntries } = opts;
  const entries: Iso9660PathTableEntry[] = [];
  let omittedEntries = 0;
  let entryCount = 0;
  let cursor = 0;

  while (cursor + 8 <= bytes.length) {
    const identifierLength = bytes[cursor] ?? 0;
    const extentLocationLba = readUint32Le(bytes, cursor + 2);
    const parentDirectoryIndex = readUint16Le(bytes, cursor + 6);

    const nameStart = cursor + 8;
    const nameEnd = nameStart + identifierLength;
    if (nameEnd > bytes.length) {
      pushIssue(`Truncated path table entry at ${formatOffsetHex(absoluteBaseOffset + cursor)}.`);
      break;
    }
    const nameBytes = bytes.subarray(nameStart, nameEnd);
    const identifier =
      identifierLength === 1 && nameBytes[0] === 0x00
        ? "/"
        : decodeStringField(nameBytes, 0, nameBytes.length, encoding);

    entryCount += 1;
    const entry: Iso9660PathTableEntry = {
      index: entryCount,
      identifier,
      extentLocationLba,
      parentDirectoryIndex
    };
    if (entries.length < maxEntries) {
      entries.push(entry);
    } else {
      omittedEntries += 1;
    }

    const padding = identifierLength % 2 === 0 ? 0 : 1;
    cursor += 8 + identifierLength + padding;
  }

  return { entryCount, entries, omittedEntries };
};

