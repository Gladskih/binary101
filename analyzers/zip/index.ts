"use strict";

import {
  MAX_CENTRAL_DIRECTORY_BYTES,
  MIN_LOCAL_HEADER_SIZE
} from "./constants.js";
import { annotateEntryDataOffsets, parseCentralDirectoryEntries } from "./central-directory.js";
import { getSafeNumber, readDataView } from "./io.js";
import { findZip64Locator, parseEocd, parseZip64Eocd, readTailForEocd } from "./eocd.js";
import type { ZipParseResult } from "./types.js";

const parseZip = async (file: File): Promise<ZipParseResult | null> => {
  const issues: string[] = [];
  const { baseOffset, dv: tailView } = await readTailForEocd(file);
  const eocd = parseEocd(tailView, baseOffset);
  if (!eocd) return null;
  const zip64Locator = findZip64Locator(tailView, baseOffset);
  const zip64 = zip64Locator ? await parseZip64Eocd(file, zip64Locator, issues) : null;
  const expectsZip64 =
    eocd.entriesThisDisk === 0xffff ||
    eocd.totalEntries === 0xffff ||
    eocd.centralDirSize === 0xffffffff ||
    eocd.centralDirOffset === 0xffffffff;
  if (expectsZip64) {
    if (!zip64Locator) {
      issues.push(
        "EOCD fields use ZIP64 placeholders but ZIP64 locator was not found."
      );
    } else if (!zip64) {
      issues.push(
        "ZIP64 metadata could not be read even though EOCD fields require it."
      );
    }
  }
  const cdOffsetSource = zip64?.centralDirOffset ?? eocd.centralDirOffset;
  const cdSizeSource = zip64?.centralDirSize ?? eocd.centralDirSize;
  const cdOffset = getSafeNumber(cdOffsetSource);
  const cdSize = getSafeNumber(cdSizeSource);
  if (cdOffset == null || cdSize == null) {
    issues.push("Central directory offset or size is outside supported range.");
    return { eocd, zip64Locator, zip64, centralDirectory: null, issues };
  }
  const cdEnd = cdOffset + cdSize;
  const fileSize = file.size || 0;
  const truncated = cdEnd > fileSize;
  if (truncated) {
    issues.push("Central directory extends beyond the file size.");
  }
  const limitedSize = Math.min(cdSize, MAX_CENTRAL_DIRECTORY_BYTES, fileSize - cdOffset);
  const cdView = await readDataView(file, cdOffset, limitedSize);
  if (!cdView) {
    issues.push("Central directory could not be read.");
    return { eocd, zip64Locator, zip64, centralDirectory: null, issues };
  }
  const entries = parseCentralDirectoryEntries(cdView, issues);
  if (eocd && entries.length !== eocd.totalEntries) {
    issues.push(
      `EOCD reports ${eocd.totalEntries} entries but parsed ${entries.length}.`
    );
  }
  await annotateEntryDataOffsets(file, entries);
  const result: ZipParseResult = {
    eocd,
    zip64Locator,
    zip64,
    centralDirectory: {
      offset: cdOffset,
      size: cdSize,
      parsedSize: cdView.byteLength,
      truncated,
      entries
    },
    issues
  };
  return result;
};

export { MIN_LOCAL_HEADER_SIZE, parseZip };
export type {
  ZipCentralDirectoryEntry,
  ZipCentralDirectoryInfo,
  ZipEndOfCentralDirectory,
  ZipParseResult,
  Zip64EndOfCentralDirectory,
  Zip64Locator,
  ZipCentralDirectoryEntryLocalHeaderInfo
} from "./types.js";
