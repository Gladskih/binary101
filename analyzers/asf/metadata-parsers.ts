"use strict";

import { parseObjectList, guidToString, numberOrString, readUint64, readUnicodeString } from "./shared.js";
import type {
  AsfCodecEntry,
  AsfContentDescription,
  AsfExtendedDescriptor,
  AsfHeaderExtension
} from "./types.js";

export const parseContentDescription = (
  dv: DataView,
  start: number,
  length: number,
  issues: string[]
): AsfContentDescription | null => {
  if (length < 10) {
    issues.push("Content description object is truncated.");
    return null;
  }
  const lengths = [
    dv.getUint16(start, true),
    dv.getUint16(start + 2, true),
    dv.getUint16(start + 4, true),
    dv.getUint16(start + 6, true),
    dv.getUint16(start + 8, true)
  ];
  let cursor = start + 10;
  const strings: string[] = [];
  let truncated = false;
  for (const len of lengths) {
    if (cursor + len > start + length) truncated = true;
    const safeLength = Math.max(0, Math.min(len, start + length - cursor));
    strings.push(readUnicodeString(dv, cursor, safeLength));
    cursor += len;
  }
  return {
    title: strings[0] || "",
    author: strings[1] || "",
    copyright: strings[2] || "",
    description: strings[3] || "",
    rating: strings[4] || "",
    truncated
  };
};

export const parseExtendedContent = (
  dv: DataView,
  start: number,
  length: number,
  issues: string[]
): AsfExtendedDescriptor[] => {
  if (length < 2) {
    issues.push("Extended content description object is truncated.");
    return [];
  }
  let cursor = start + 2;
  const count = dv.getUint16(start, true);
  const descriptors: AsfExtendedDescriptor[] = [];
  for (let i = 0; i < count && cursor < start + length; i += 1) {
    if (cursor + 2 > start + length) break;
    const nameLen = dv.getUint16(cursor, true);
    cursor += 2;
    const name = readUnicodeString(dv, cursor, Math.min(nameLen, start + length - cursor));
    cursor += nameLen;
    if (cursor + 4 > start + length) break;
    const valueType = dv.getUint16(cursor, true);
    const valueLen = dv.getUint16(cursor + 2, true);
    cursor += 4;
    const truncated = cursor + valueLen > start + length;
    const safeLen = Math.max(0, Math.min(valueLen, start + length - cursor));
    let value = "";
    if (valueType === 0) value = readUnicodeString(dv, cursor, safeLen);
    else if (valueType === 1) value = `Binary (${safeLen} bytes)`;
    else if (valueType === 2) value = safeLen >= 2 && dv.getUint16(cursor, true) !== 0 ? "true" : "false";
    else if (valueType === 3) value = safeLen >= 4 ? String(dv.getUint32(cursor, true)) : "";
    else if (valueType === 4) value = safeLen >= 8 ? numberOrString(readUint64(dv, cursor))?.toString() || "" : "";
    else if (valueType === 5) value = safeLen >= 2 ? String(dv.getUint16(cursor, true)) : "";
    else value = `Type ${valueType} (${safeLen} bytes)`;
    descriptors.push({
      name,
      valueType:
        valueType === 0
          ? "Unicode string"
          : valueType === 1
            ? "Binary blob"
            : valueType === 2
              ? "Boolean (WORD)"
              : valueType === 3
                ? "DWORD"
                : valueType === 4
                  ? "QWORD"
                  : valueType === 5
                    ? "WORD"
                    : `Type ${valueType}`,
      value,
      truncated
    });
    cursor += valueLen;
  }
  return descriptors;
};

export const parseCodecList = (
  dv: DataView,
  start: number,
  length: number,
  issues: string[]
): AsfCodecEntry[] => {
  if (length < 20) {
    issues.push("Codec list object is truncated.");
    return [];
  }
  const entries: AsfCodecEntry[] = [];
  const codecCount = dv.getUint32(start + 16, true);
  let cursor = start + 20;
  for (let i = 0; i < codecCount && cursor < start + length; i += 1) {
    if (cursor + 2 > start + length) break;
    const typeCode = dv.getUint16(cursor, true);
    const type = typeCode === 1 ? "Video codec" : typeCode === 2 ? "Audio codec" : "Unknown codec";
    cursor += 2;
    const nameLen = dv.getUint16(cursor, true);
    cursor += 2;
    const name = readUnicodeString(dv, cursor, Math.min(nameLen, start + length - cursor));
    cursor += nameLen;
    if (cursor + 2 > start + length) break;
    const descLen = dv.getUint16(cursor, true);
    cursor += 2;
    const description = readUnicodeString(dv, cursor, Math.min(descLen, start + length - cursor));
    cursor += descLen;
    if (cursor + 2 > start + length) break;
    const infoLen = dv.getUint16(cursor, true);
    cursor += 2;
    const truncated = cursor + infoLen > start + length;
    cursor += infoLen;
    entries.push({ type, name, description, infoLength: infoLen, truncated });
  }
  return entries;
};

export const parseHeaderExtension = (
  dv: DataView,
  start: number,
  length: number,
  issues: string[]
): AsfHeaderExtension => {
  const truncated = length < 22;
  const reserved1 = length >= 16 ? guidToString(dv, start) : null;
  const reserved2 = length >= 18 ? dv.getUint16(start + 16, true) : null;
  const dataSize = length >= 22 ? dv.getUint32(start + 18, true) : null;
  const objects = dataSize != null
    ? parseObjectList(dv, start + 22, Math.min(start + length, start + 22 + dataSize), issues, "Header extension").objects
    : [];
  if (dataSize == null) issues.push("Header extension does not expose extension data size.");
  return { reserved1, reserved2, dataSize, objects, truncated };
};
