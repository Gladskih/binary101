"use strict";

import type {
  TgaColorCorrectionTableSummary,
  TgaExtensionArea,
  TgaPostageStampSummary,
  TgaScanLineTableSummary
} from "./types.js";
import {
  TGA_COLOR_CORRECTION_TABLE_SIZE,
  TGA_EXTENSION_AREA_SIZE,
  decodeFixedString,
  readUint16le,
  readUint32le,
  readUint8
} from "./tga-parsing.js";

const pad2 = (value: number): string => String(value).padStart(2, "0");

const formatTimestamp = (
  month: number | null,
  day: number | null,
  year: number | null,
  hour: number | null,
  minute: number | null,
  second: number | null,
  pushIssue: (message: string) => void
): string | null => {
  const fields = [month, day, year, hour, minute, second];
  if (fields.every(value => value == null)) return null;
  if (fields.every(value => value === 0)) return null;
  if (month != null && (month < 1 || month > 12)) pushIssue(`Timestamp month is out of range (${month}).`);
  if (day != null && (day < 1 || day > 31)) pushIssue(`Timestamp day is out of range (${day}).`);
  if (hour != null && hour > 23) pushIssue(`Timestamp hour is out of range (${hour}).`);
  if (minute != null && minute > 59) pushIssue(`Timestamp minute is out of range (${minute}).`);
  if (second != null && second > 59) pushIssue(`Timestamp second is out of range (${second}).`);
  const y = year == null ? "????" : String(year).padStart(4, "0");
  const mo = month == null ? "??" : pad2(month);
  const d = day == null ? "??" : pad2(day);
  const h = hour == null ? "??" : pad2(hour);
  const mi = minute == null ? "??" : pad2(minute);
  const s = second == null ? "??" : pad2(second);
  return `${y}-${mo}-${d} ${h}:${mi}:${s}`;
};

export const parseTgaExtensionArea = async (
  file: File,
  offset: number,
  pixelSizeBytes: number | null,
  imageHeight: number | null,
  pushIssue: (message: string) => void
): Promise<TgaExtensionArea | null> => {
  if (offset <= 0 || offset >= file.size) return null;
  const end = Math.min(file.size, offset + TGA_EXTENSION_AREA_SIZE);
  const bytes = new Uint8Array(await file.slice(offset, end).arrayBuffer());
  const truncated = bytes.length < TGA_EXTENSION_AREA_SIZE;

  const size = readUint16le(bytes, 0);
  if (size != null && size !== TGA_EXTENSION_AREA_SIZE) {
    pushIssue(`Extension area size field is ${size}, expected ${TGA_EXTENSION_AREA_SIZE}.`);
  }

  const authorName = decodeFixedString(bytes, 2, 41) || null;
  const authorComment = decodeFixedString(bytes, 43, 324) || null;

  const stampMonth = readUint16le(bytes, 367);
  const stampDay = readUint16le(bytes, 369);
  const stampYear = readUint16le(bytes, 371);
  const stampHour = readUint16le(bytes, 373);
  const stampMinute = readUint16le(bytes, 375);
  const stampSecond = readUint16le(bytes, 377);
  const timestamp = formatTimestamp(
    stampMonth,
    stampDay,
    stampYear,
    stampHour,
    stampMinute,
    stampSecond,
    pushIssue
  );

  const jobName = decodeFixedString(bytes, 379, 41) || null;
  const jobHour = readUint16le(bytes, 420);
  const jobMinute = readUint16le(bytes, 422);
  const jobSecond = readUint16le(bytes, 424);
  const jobTime =
    jobHour == null || jobMinute == null || jobSecond == null || (jobHour === 0 && jobMinute === 0 && jobSecond === 0)
      ? null
      : `${jobHour}h ${jobMinute}m ${jobSecond}s`;

  const softwareId = decodeFixedString(bytes, 426, 41) || null;
  const versionNumber = readUint16le(bytes, 467);
  const versionLetter = readUint8(bytes, 469);
  const softwareVersion =
    versionNumber == null || versionNumber === 0
      ? null
      : `${versionNumber}${versionLetter != null && versionLetter >= 0x20 ? String.fromCharCode(versionLetter) : ""}`;

  const keyColor = readUint32le(bytes, 470);
  const pixelNumerator = readUint16le(bytes, 474);
  const pixelDenominator = readUint16le(bytes, 476);
  const pixelAspectRatio =
    pixelNumerator && pixelDenominator ? pixelNumerator / pixelDenominator : null;

  const gammaNumerator = readUint16le(bytes, 478);
  const gammaDenominator = readUint16le(bytes, 480);
  const gamma = gammaNumerator && gammaDenominator ? gammaNumerator / gammaDenominator : null;

  const colorOffsetValue = readUint32le(bytes, 482);
  const stampOffsetValue = readUint32le(bytes, 486);
  const scanOffsetValue = readUint32le(bytes, 490);
  const attributesType = readUint8(bytes, 494);

  const colorCorrectionTable: TgaColorCorrectionTableSummary | null = colorOffsetValue
    ? {
        offset: colorOffsetValue,
        expectedBytes: TGA_COLOR_CORRECTION_TABLE_SIZE,
        truncated: colorOffsetValue + TGA_COLOR_CORRECTION_TABLE_SIZE > file.size
      }
    : null;

  let postageStamp: TgaPostageStampSummary | null = null;
  if (stampOffsetValue) {
    const headerEnd = Math.min(file.size, stampOffsetValue + 2);
    const stampBytes = new Uint8Array(await file.slice(stampOffsetValue, headerEnd).arrayBuffer());
    const stampWidth = readUint8(stampBytes, 0);
    const stampHeight = readUint8(stampBytes, 1);
    const expectedBytes =
      stampWidth != null && stampHeight != null && pixelSizeBytes != null
        ? 2 + stampWidth * stampHeight * pixelSizeBytes
        : null;
    postageStamp = {
      offset: stampOffsetValue,
      width: stampWidth,
      height: stampHeight,
      expectedBytes,
      truncated: expectedBytes != null ? stampOffsetValue + expectedBytes > file.size : stampBytes.length < 2
    };
  }

  const scanLineTable: TgaScanLineTableSummary | null = scanOffsetValue
    ? {
        offset: scanOffsetValue,
        expectedBytes: imageHeight != null ? imageHeight * 4 : null,
        truncated:
          imageHeight != null ? scanOffsetValue + imageHeight * 4 > file.size : scanOffsetValue > file.size
      }
    : null;

  return {
    offset,
    size,
    authorName,
    authorComment,
    timestamp,
    jobName,
    jobTime,
    softwareId,
    softwareVersion,
    keyColor,
    pixelAspectRatio,
    gamma,
    colorCorrectionTable,
    postageStamp,
    scanLineTable,
    attributesType,
    truncated
  };
};

