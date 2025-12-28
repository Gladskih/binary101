"use strict";

import { alignUpTo, toHex32 } from "../../binary-utils.js";
import type {
  Iso9660DirectoryEntrySummary,
  Iso9660DirectoryRecord,
  Iso9660StringEncoding
} from "./types.js";
import {
  decodeStringField,
  parseRecordingDateTime,
  readBothEndianUint16,
  readBothEndianUint32
} from "./iso-parsing.js";

const formatOffsetHex = (offset: number): string => toHex32(offset >>> 0, 8);

const normalizeFileIdentifier = (value: string | null): { name: string | null; version: number | null } => {
  if (!value) return { name: null, version: null };
  const match = /^(.*);([0-9]+)$/.exec(value);
  if (!match) return { name: value, version: null };
  const base = match[1] ?? value;
  const version = match[2] != null ? Number.parseInt(match[2], 10) : null;
  return { name: base, version: Number.isFinite(version) ? version : null };
};

export const parseDirectoryRecord = (
  bytes: Uint8Array,
  offset: number,
  absoluteBaseOffset: number,
  encoding: Iso9660StringEncoding,
  pushIssue: (message: string) => void,
  opts?: { zeroIdentifierMeaning?: "root" | "dot" }
): Iso9660DirectoryRecord | null => {
  if (offset < 0 || offset + 1 > bytes.length) return null;
  const recordLength = bytes[offset] ?? 0;
  if (recordLength === 0) return null;
  if (recordLength < 34) {
    pushIssue(`Directory record at ${formatOffsetHex(absoluteBaseOffset + offset)} is unusually short (${recordLength} bytes).`);
  }
  if (offset + recordLength > bytes.length) {
    pushIssue(`Truncated directory record at ${formatOffsetHex(absoluteBaseOffset + offset)} (length ${recordLength}).`);
    return null;
  }

  const extendedAttributeRecordLength = bytes[offset + 1] ?? 0;
  const extentLocationLba = readBothEndianUint32(bytes, offset + 2, absoluteBaseOffset, "Extent LBA", pushIssue);
  const dataLength = readBothEndianUint32(bytes, offset + 10, absoluteBaseOffset, "Data length", pushIssue);
  const { text: recordingDateTime, utcOffsetMinutes } = parseRecordingDateTime(bytes, offset + 18);
  const fileFlags = bytes[offset + 25] ?? 0;
  const fileUnitSize = bytes[offset + 26] ?? 0;
  const interleaveGapSize = bytes[offset + 27] ?? 0;
  const volumeSequenceNumber = readBothEndianUint16(
    bytes,
    offset + 28,
    absoluteBaseOffset,
    "Volume sequence number",
    pushIssue
  );

  const fileIdentifierLength = bytes[offset + 32] ?? 0;
  const identifierOffset = offset + 33;
  const recordEnd = offset + recordLength;
  if (identifierOffset + fileIdentifierLength > recordEnd) {
    pushIssue(
      `Directory record at ${formatOffsetHex(absoluteBaseOffset + offset)} declares file identifier bytes past record end.`
    );
    return null;
  }

  const identifierBytes = bytes.subarray(identifierOffset, identifierOffset + fileIdentifierLength);
  const isZero = fileIdentifierLength === 1 && identifierBytes[0] === 0x00;
  const isOne = fileIdentifierLength === 1 && identifierBytes[0] === 0x01;
  const zeroMeaning = opts?.zeroIdentifierMeaning || "dot";

  let fileIdentifierRaw: string | null = null;
  let fileIdentifier: string | null = null;
  let fileVersion: number | null = null;
  let isDotEntry = false;
  let isDotDotEntry = false;

  if (isZero && zeroMeaning === "root") {
    fileIdentifierRaw = "/";
    fileIdentifier = "/";
  } else if (isZero) {
    fileIdentifierRaw = ".";
    fileIdentifier = ".";
    isDotEntry = true;
  } else if (isOne) {
    fileIdentifierRaw = "..";
    fileIdentifier = "..";
    isDotDotEntry = true;
  } else {
    fileIdentifierRaw = decodeStringField(identifierBytes, 0, identifierBytes.length, encoding);
    const normalized = normalizeFileIdentifier(fileIdentifierRaw);
    fileIdentifier = normalized.name;
    fileVersion = normalized.version;
  }

  const isDirectory = (fileFlags & 0x02) !== 0 || isDotEntry || isDotDotEntry || zeroMeaning === "root";
  const paddingBytes = fileIdentifierLength % 2 === 0 ? 1 : 0;
  const systemUseStart = identifierOffset + fileIdentifierLength + paddingBytes;
  const systemUseLength = Math.max(0, recordEnd - systemUseStart);

  return {
    recordLength,
    extendedAttributeRecordLength,
    extentLocationLba,
    dataLength,
    recordingDateTime,
    utcOffsetMinutes,
    fileFlags,
    fileUnitSize,
    interleaveGapSize,
    volumeSequenceNumber,
    fileIdentifierRaw,
    fileIdentifier,
    fileVersion,
    isDirectory,
    isDotEntry,
    isDotDotEntry,
    systemUseLength
  };
};

export type DirectoryScanResult = {
  totalEntries: number;
  fileCount: number;
  directoryCount: number;
  childDirectories: Array<{ name: string; extentLocationLba: number; dataLength: number | null }>;
  entries: Iso9660DirectoryEntrySummary[];
  omittedEntries: number;
};

export const scanDirectoryBytes = (opts: {
  bytes: Uint8Array;
  absoluteBaseOffset: number;
  blockSize: number;
  encoding: Iso9660StringEncoding;
  pushIssue: (message: string) => void;
  maxEntries: number;
}): DirectoryScanResult => {
  const { bytes, absoluteBaseOffset, blockSize, encoding, pushIssue, maxEntries } = opts;
  let cursor = 0;
  let totalEntries = 0;
  let fileCount = 0;
  let directoryCount = 0;
  let omittedEntries = 0;
  const entries: Iso9660DirectoryEntrySummary[] = [];
  const childDirectories: DirectoryScanResult["childDirectories"] = [];

  while (cursor < bytes.length) {
    const recordLength = bytes[cursor] ?? 0;
    if (recordLength === 0) {
      const next = alignUpTo(cursor + 1, blockSize);
      if (next <= cursor) break;
      cursor = Math.min(bytes.length, next);
      continue;
    }
    if (cursor + recordLength > bytes.length) {
      pushIssue(`Truncated directory area near ${formatOffsetHex(absoluteBaseOffset + cursor)}.`);
      break;
    }

    const record = parseDirectoryRecord(bytes, cursor, absoluteBaseOffset, encoding, pushIssue);
    if (record) {
      totalEntries += 1;
      const kind = record.isDotEntry || record.isDotDotEntry ? "special" : record.isDirectory ? "directory" : "file";
      if (kind === "file") fileCount += 1;
      if (kind === "directory" && !record.isDotEntry && !record.isDotDotEntry) directoryCount += 1;

      const name = record.fileIdentifier || record.fileIdentifierRaw || "(unnamed)";
      if (entries.length < maxEntries) {
        entries.push({
          name,
          kind,
          extentLocationLba: record.extentLocationLba,
          dataLength: record.dataLength,
          fileFlags: record.fileFlags,
          recordingDateTime: record.recordingDateTime
        });
      } else {
        omittedEntries += 1;
      }

      if (kind === "directory" && record.extentLocationLba != null && !record.isDotEntry && !record.isDotDotEntry) {
        childDirectories.push({
          name,
          extentLocationLba: record.extentLocationLba,
          dataLength: record.dataLength
        });
      }
    }

    cursor += recordLength;
  }

  return {
    totalEntries,
    fileCount,
    directoryCount,
    childDirectories,
    entries,
    omittedEntries
  };
};

