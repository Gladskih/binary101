"use strict";

import {
  ASF_CODEC_LIST_GUID,
  ASF_CONTENT_DESCRIPTION_GUID,
  ASF_DATA_GUID,
  ASF_EXTENDED_CONTENT_DESCRIPTION_GUID,
  ASF_FILE_PROPERTIES_GUID,
  ASF_HEADER_EXTENSION_GUID,
  ASF_HEADER_GUID,
  ASF_STREAM_PROPERTIES_GUID,
  MAX_OBJECTS,
  OBJECT_HEADER_SIZE
} from "./constants.js";
import {
  parseCodecList,
  parseContentDescription,
  parseExtendedContent,
  parseHeaderExtension
} from "./metadata-parsers.js";
import { guidToString, nameForGuid, parseObjectList, readUint64 } from "./shared.js";
import { parseDataObject, parseFileProperties, parseStreamProperties } from "./stream-parsers.js";
import type { AsfParseResult, AsfStreamProperties } from "./types.js";

const MAX_OBJECT_READ = 2 * 1024 * 1024;
const HEADER_FIELDS_SIZE = 6;
const maxSafe = BigInt(Number.MAX_SAFE_INTEGER);

const buildStreamSummary = (streams: AsfStreamProperties[]): string => {
  const audio = streams.filter(s => s.typeSpecific?.kind === "audio").length;
  const video = streams.filter(s => s.typeSpecific?.kind === "video").length;
  if (!audio && !video) return "No streams parsed";
  return `${audio} audio / ${video} video streams`;
};

export const parseAsf = async (file: File): Promise<AsfParseResult | null> => {
  if (file.size < OBJECT_HEADER_SIZE) return null;
  const probeView = new DataView(await file.slice(0, Math.min(file.size, 64)).arrayBuffer());
  if (guidToString(probeView, 0) !== ASF_HEADER_GUID) return null;

  const issues: string[] = [];
  const objects: AsfParseResult["objects"] = [];
  let header: AsfParseResult["header"] = null;
  let fileProperties: AsfParseResult["fileProperties"] = null;
  const streams: AsfStreamProperties[] = [];
  let contentDescription: AsfParseResult["contentDescription"] = null;
  let headerExtension: AsfParseResult["headerExtension"] = null;
  const extendedContent: AsfParseResult["extendedContent"] = [];
  const codecList: AsfParseResult["codecList"] = [];
  let dataObject: AsfParseResult["dataObject"] = null;
  let truncatedObjects = 0;
  let offset = 0;

  while (offset + OBJECT_HEADER_SIZE <= file.size && objects.length < MAX_OBJECTS) {
    const headerBuf = new DataView(await file.slice(offset, offset + OBJECT_HEADER_SIZE).arrayBuffer());
    const guid = guidToString(headerBuf, 0);
    const sizeBig = readUint64(headerBuf, 16);
    const size = sizeBig && sizeBig > 0n && sizeBig <= maxSafe ? Number(sizeBig) : null;
    if (size == null || size < OBJECT_HEADER_SIZE) {
      issues.push(`Object at ${offset} has invalid size; stopping parse.`);
      break;
    }
    const available = Math.min(size, file.size - offset, MAX_OBJECT_READ);
    const objectView = new DataView(await file.slice(offset, offset + available).arrayBuffer());
    const truncated = offset + size > file.size || size > available;
    if (truncated) truncatedObjects += 1;
    const payloadStart = OBJECT_HEADER_SIZE;
    const payloadLength = Math.max(0, Math.min(size - OBJECT_HEADER_SIZE, objectView.byteLength - payloadStart));

    if (guid === ASF_HEADER_GUID) {
      const objectCount = payloadLength >= 4 ? objectView.getUint32(payloadStart, true) : null;
      const reserved1 = payloadLength >= 5 ? objectView.getUint8(payloadStart + 4) : null;
      const reserved2 = payloadLength >= 6 ? objectView.getUint8(payloadStart + 5) : null;
      const childStart = payloadStart + HEADER_FIELDS_SIZE;
      const headerEnd = Math.min(objectView.byteLength, size);
      const children = childStart < headerEnd
        ? parseObjectList(objectView, childStart, headerEnd, issues, "Header")
        : { objects: [], parsedBytes: 0, truncatedCount: 0 };
      truncatedObjects += children.truncatedCount;
      header = { size, objectCount, reserved1, reserved2, children: children.objects, truncated };

      for (const child of children.objects) {
        const childStartOff = child.offset + OBJECT_HEADER_SIZE;
        const childLen = Math.max(
          0,
          Math.min((child.size ?? 0) - OBJECT_HEADER_SIZE, headerEnd - childStartOff)
        );
        if (child.guid === ASF_FILE_PROPERTIES_GUID) {
          fileProperties = parseFileProperties(objectView, childStartOff, childLen, issues);
        } else if (child.guid === ASF_STREAM_PROPERTIES_GUID) {
          const parsed = parseStreamProperties(objectView, childStartOff, childLen, issues);
          if (parsed) streams.push(parsed);
        } else if (child.guid === ASF_CONTENT_DESCRIPTION_GUID) {
          contentDescription = parseContentDescription(objectView, childStartOff, childLen, issues);
        } else if (child.guid === ASF_EXTENDED_CONTENT_DESCRIPTION_GUID) {
          extendedContent.push(...parseExtendedContent(objectView, childStartOff, childLen, issues));
        } else if (child.guid === ASF_CODEC_LIST_GUID) {
          codecList.push(...parseCodecList(objectView, childStartOff, childLen, issues));
        } else if (child.guid === ASF_HEADER_EXTENSION_GUID) {
          headerExtension = parseHeaderExtension(objectView, childStartOff, childLen, issues);
          if (headerExtension?.truncated) truncatedObjects += 1;
        }
      }
    } else if (guid === ASF_DATA_GUID) {
      const parsed = parseDataObject(objectView, payloadStart, payloadLength, offset, size, issues);
      if (parsed) dataObject = parsed;
    }

    objects.push({ guid, name: nameForGuid(guid), offset, size, truncated });
    offset += size;
  }

  const parsedBytes = offset;
  const overlayBytes = parsedBytes < file.size ? file.size - parsedBytes : 0;

  return {
    header,
    objects,
    fileProperties,
    streams,
    contentDescription,
    extendedContent,
    codecList,
    headerExtension,
    dataObject,
    issues,
    stats: {
      parsedObjects: objects.length,
      truncatedObjects,
      parsedBytes,
      overlayBytes
    }
  };
};

export const buildAsfLabel = (asf: AsfParseResult | null): string | null => {
  if (!asf) return null;
  const parts: string[] = [];
  const streamSummary = buildStreamSummary(asf.streams);
  if (streamSummary) parts.push(streamSummary);
  if (asf.fileProperties?.durationSeconds) parts.push(`${asf.fileProperties.durationSeconds} s`);
  if (asf.fileProperties?.maxBitrate) {
    parts.push(`${Math.round(asf.fileProperties.maxBitrate / 1000)} kbps max`);
  }
  const suffix = parts.length ? ` (${parts.join(", ")})` : "";
  return `ASF container${suffix}`;
};
