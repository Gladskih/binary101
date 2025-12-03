"use strict";

import { readAsciiString } from "../../binary-utils.js";
import {
  EOCD_SIGNATURE,
  MAX_EOCD_SCAN,
  MIN_EOCD_SIZE,
  ZIP64_EOCD_LOCATOR_SIGNATURE,
  ZIP64_EOCD_SIGNATURE
} from "./constants.js";
import { getBigUint64, getSafeNumber, readDataView } from "./io.js";
import type { Zip64EndOfCentralDirectory, Zip64Locator, ZipEndOfCentralDirectory } from "./types.js";

const readTailForEocd = async (
  file: File
): Promise<{ baseOffset: number; dv: DataView }> => {
  const fileSize = file.size || 0;
  const probeSize = Math.min(fileSize, MAX_EOCD_SCAN);
  const start = Math.max(0, fileSize - probeSize);
  const buffer = await file.slice(start, fileSize).arrayBuffer();
  return { baseOffset: start, dv: new DataView(buffer) };
};

const parseEocd = (dv: DataView, baseOffset: number): ZipEndOfCentralDirectory | null => {
  for (let i = dv.byteLength - MIN_EOCD_SIZE; i >= 0; i -= 1) {
    if (dv.getUint32(i, true) !== EOCD_SIGNATURE) continue;
    const commentLength = dv.getUint16(i + 20, true);
    if (i + MIN_EOCD_SIZE + commentLength > dv.byteLength) continue;
    const diskNumber = dv.getUint16(i + 4, true);
    const centralDirDisk = dv.getUint16(i + 6, true);
    const entriesThisDisk = dv.getUint16(i + 8, true);
    const totalEntries = dv.getUint16(i + 10, true);
    const centralDirSize = dv.getUint32(i + 12, true);
    const centralDirOffset = dv.getUint32(i + 16, true);
    const comment =
      commentLength > 0
        ? readAsciiString(dv, i + 22, Math.min(commentLength, 32768))
        : "";
    const eocd: ZipEndOfCentralDirectory = {
      offset: baseOffset + i,
      diskNumber,
      centralDirDisk,
      entriesThisDisk,
      totalEntries,
      centralDirSize,
      centralDirOffset,
      comment,
      commentLength
    };
    return eocd;
  }
  return null;
};

const findZip64Locator = (dv: DataView, baseOffset: number): Zip64Locator | null => {
  const locatorSize = 20;
  const limit = dv.byteLength - locatorSize;
  let found: Zip64Locator | null = null;
  for (let i = 0; i <= limit; i += 1) {
    if (dv.getUint32(i, true) !== ZIP64_EOCD_LOCATOR_SIGNATURE) continue;
    const diskWithEocd = dv.getUint32(i + 4, true);
    const zip64EocdOffset = getBigUint64(dv, i + 8);
    const totalDisks = dv.getUint32(i + 16, true);
    found = {
      offset: baseOffset + i,
      diskWithEocd,
      zip64EocdOffset,
      totalDisks
    };
  }
  return found;
};

const parseZip64Eocd = async (
  file: File,
  locator: Zip64Locator,
  issues: string[]
): Promise<Zip64EndOfCentralDirectory | null> => {
  const offsetNumber = getSafeNumber(locator.zip64EocdOffset);
  if (offsetNumber == null) {
    issues.push("ZIP64 EOCD offset exceeds supported range.");
    return null;
  }
  const headerView = await readDataView(file, offsetNumber, 12);
  if (!headerView || headerView.byteLength < 12) {
    issues.push("ZIP64 EOCD record is truncated or missing.");
    return null;
  }
  if (headerView.getUint32(0, true) !== ZIP64_EOCD_SIGNATURE) {
    issues.push("ZIP64 EOCD signature mismatch.");
    return null;
  }
  const recordSize = headerView.getBigUint64(4, true);
  const totalSize = getSafeNumber(recordSize + 12n);
  if (totalSize == null || totalSize > 1048576) {
    issues.push("ZIP64 EOCD record is too large to inspect.");
    return null;
  }
  const dv = await readDataView(file, offsetNumber, totalSize);
  if (!dv || dv.byteLength < 56) {
    issues.push("ZIP64 EOCD record is truncated.");
    return null;
  }
  const result: Zip64EndOfCentralDirectory = {
    offset: offsetNumber,
    size: totalSize,
    versionMadeBy: dv.getUint16(12, true),
    versionNeeded: dv.getUint16(14, true),
    diskNumber: dv.getUint32(16, true),
    centralDirDisk: dv.getUint32(20, true),
    entriesThisDisk: getBigUint64(dv, 24),
    totalEntries: getBigUint64(dv, 32),
    centralDirSize: getBigUint64(dv, 40),
    centralDirOffset: getBigUint64(dv, 48)
  };
  return result;
};

export { findZip64Locator, parseEocd, parseZip64Eocd, readTailForEocd };
