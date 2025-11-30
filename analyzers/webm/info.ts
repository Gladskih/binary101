"use strict";

import { MAX_EBML_HEADER_BYTES, MAX_INFO_BYTES } from "./constants.js";
import {
  clampReadLength,
  readDate,
  readElementHeader,
  readUnsigned,
  readUtf8,
  readFloat
} from "./ebml.js";
import type { EbmlElementHeader } from "./ebml.js";
import type { Issues, WebmEbmlHeader, WebmInfo, WebmParseResult } from "./types.js";
import { bufferToHex } from "../../binary-utils.js";

export const parseEbmlHeader = async (
  file: File,
  header: EbmlElementHeader,
  issues: Issues
): Promise<{ ebmlHeader: WebmEbmlHeader; docType: string | null }> => {
  const { length, truncated } = clampReadLength(file.size, header.dataOffset, header.size, MAX_EBML_HEADER_BYTES);
  const dv = new DataView(await file.slice(header.dataOffset, header.dataOffset + length).arrayBuffer());
  const limit = header.size != null ? Math.min(header.size, dv.byteLength) : dv.byteLength;
  if (truncated) issues.push("EBML header is truncated; parsed fields may be incomplete.");
  const ebmlHeader: WebmEbmlHeader = {
    docType: null,
    docTypeVersion: null,
    docTypeReadVersion: null,
    ebmlVersion: null,
    ebmlReadVersion: null,
    maxIdLength: null,
    maxSizeLength: null
  };
  let cursor = 0;
  while (cursor < limit) {
    const child = readElementHeader(dv, cursor, header.dataOffset + cursor, issues);
    if (!child || child.headerSize === 0) break;
    const dataStart = cursor + child.headerSize;
    const available = Math.min(child.size ?? 0, limit - dataStart);
    if (child.id === 0x4282 && available > 0) {
      ebmlHeader.docType = readUtf8(dv, dataStart, available).trim() || null;
    } else if (child.id === 0x4287) {
      const value = readUnsigned(dv, dataStart, available, issues, "DocTypeVersion");
      ebmlHeader.docTypeVersion = value != null ? Number(value) : null;
    } else if (child.id === 0x4285) {
      const value = readUnsigned(dv, dataStart, available, issues, "DocTypeReadVersion");
      ebmlHeader.docTypeReadVersion = value != null ? Number(value) : null;
    } else if (child.id === 0x4286) {
      const value = readUnsigned(dv, dataStart, available, issues, "EBMLVersion");
      ebmlHeader.ebmlVersion = value != null ? Number(value) : null;
    } else if (child.id === 0x42f7) {
      const value = readUnsigned(dv, dataStart, available, issues, "EBMLReadVersion");
      ebmlHeader.ebmlReadVersion = value != null ? Number(value) : null;
    } else if (child.id === 0x42f2) {
      const value = readUnsigned(dv, dataStart, available, issues, "EBMLMaxIDLength");
      ebmlHeader.maxIdLength = value != null ? Number(value) : null;
    } else if (child.id === 0x42f3) {
      const value = readUnsigned(dv, dataStart, available, issues, "EBMLMaxSizeLength");
      ebmlHeader.maxSizeLength = value != null ? Number(value) : null;
    }
    if (child.size == null || child.size === 0) break;
    cursor += child.headerSize + (child.size ?? 0);
  }
  return { ebmlHeader, docType: ebmlHeader.docType };
};

export const validateDocTypeCompatibility = (
  issues: Issues,
  docTypeLower: string,
  header: WebmParseResult["ebmlHeader"]
): void => {
  if (!docTypeLower) return;
  if (header.docTypeReadVersion != null && header.docTypeVersion != null) {
    if (header.docTypeReadVersion > header.docTypeVersion) {
      issues.push("DocTypeReadVersion is greater than DocTypeVersion.");
    }
  }
  if (docTypeLower === "webm") {
    if (header.docTypeReadVersion != null && header.docTypeReadVersion > 2) {
      issues.push("DocTypeReadVersion exceeds WebM spec (should be <= 2).");
    }
    if (header.docTypeVersion != null && header.docTypeVersion > 4) {
      issues.push("DocTypeVersion exceeds WebM spec (should be <= 4).");
    }
  }
};

export const parseInfo = async (
  file: File,
  infoHeader: EbmlElementHeader,
  timecodeScaleFallback: number,
  issues: Issues
): Promise<WebmInfo> => {
  const { length, truncated } = clampReadLength(file.size, infoHeader.dataOffset, infoHeader.size, MAX_INFO_BYTES);
  const dv = new DataView(await file.slice(infoHeader.dataOffset, infoHeader.dataOffset + length).arrayBuffer());
  const limit = infoHeader.size != null ? Math.min(infoHeader.size, dv.byteLength) : dv.byteLength;
  const info: WebmInfo = {
    timecodeScale: timecodeScaleFallback,
    duration: null,
    durationSeconds: null,
    muxingApp: null,
    writingApp: null,
    title: null,
    dateUtc: null,
    segmentUid: null
  };
  let cursor = 0;
  while (cursor < limit) {
    const child = readElementHeader(dv, cursor, infoHeader.dataOffset + cursor, issues);
    if (!child || child.headerSize === 0) break;
    const dataStart = cursor + child.headerSize;
    const available = Math.min(child.size ?? 0, limit - dataStart);
    if (child.id === 0x2ad7b1 && available > 0) {
      const value = readUnsigned(dv, dataStart, available, issues, "TimecodeScale");
      info.timecodeScale = value != null ? Number(value) : timecodeScaleFallback;
    } else if (child.id === 0x4489 && available > 0) {
      info.duration = readFloat(dv, dataStart, available, issues, "Duration");
    } else if (child.id === 0x4d80 && available > 0) {
      info.muxingApp = readUtf8(dv, dataStart, available);
    } else if (child.id === 0x5741 && available > 0) {
      info.writingApp = readUtf8(dv, dataStart, available);
    } else if (child.id === 0x7ba9 && available > 0) {
      info.title = readUtf8(dv, dataStart, available);
    } else if (child.id === 0x4461 && available > 0) {
      info.dateUtc = readDate(dv, dataStart, available, issues);
    } else if (child.id === 0x73a4 && available > 0) {
      const uidBytes = new Uint8Array(
        dv.buffer,
        dv.byteOffset + dataStart,
        Math.min(available, dv.byteLength - dataStart)
      );
      info.segmentUid = bufferToHex(uidBytes);
    }
    if (child.size == null) break;
    cursor += child.headerSize + child.size;
  }
  if (info.duration != null && info.timecodeScale != null) {
    info.durationSeconds = (info.duration * info.timecodeScale) / 1e9;
  }
  if (truncated) issues.push("Segment Info section is truncated; some fields may be missing.");
  return info;
};
