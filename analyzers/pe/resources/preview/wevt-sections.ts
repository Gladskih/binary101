"use strict";

import { readGuid } from "../../type-library/reader.js";
import type { ResourceWevtMap, ResourceWevtMetadata, ResourceWevtTemplate } from "./types.js";
import { parseWevtBinXml } from "./wevt-binxml.js";
import { parseWevtMaps } from "./wevt-maps.js";

// Element layouts: libfwevt, Windows Event manifest binary format, §§4–12.
// https://github.com/libyal/libfwevt/blob/main/documentation/Windows%20Event%20manifest%20binary%20format.asciidoc
const within = (offset: number, size: number, end: number): boolean =>
  // Public offsets are checked here; sizes come from fixed layouts or unsigned fields.
  Number.isSafeInteger(offset) && offset >= 0 && size <= end - offset;

const signature = (bytes: Uint8Array, offset: number): string =>
  String.fromCharCode(...bytes.subarray(offset, offset + 4));

const readName = (
  bytes: Uint8Array, view: DataView, offset: number, end: number, issues: string[]
): string | null => {
  // libfwevt sections 4.2, 5.2 and 7.3: u32 total size plus UTF-16LE string and NUL.
  if (offset === 0) return null;
  if (!within(offset, 4, end)) {
    issues.push("WEVT name offset is invalid.");
    return null;
  }
  const size = view.getUint32(offset, true);
  if (size < 6 || !within(offset, size, end) || size % 2) {
    issues.push("WEVT UTF-16 name is invalid or truncated.");
    return null;
  }
  const text = new TextDecoder("utf-16le").decode(bytes.subarray(offset + 4, offset + size));
  return text.replace(/\0.*/su, "");
};

// libfwevt sections 4.1, 5.1, 7.1, 10.1 and 11.1 give each record size and field offset.
const metadataShape = (kind: string): { size: number; name: number; message: number } | null => {
  switch (kind) {
    case "CHAN": return { size: 16, name: 4, message: 12 };
    case "KEYW": return { size: 16, name: 12, message: 8 };
    case "LEVL":
    case "OPCO": return { size: 12, name: 8, message: 4 };
    case "TASK": return { size: 28, name: 24, message: 4 };
    default: return null;
  }
};

const readMetadata = (
  bytes: Uint8Array, view: DataView, offset: number, tableEnd: number,
  manifestEnd: number, kind: string, issues: string[]
): ResourceWevtMetadata[] => {
  const shape = metadataShape(kind);
  if (!shape) return [];
  const count = view.getUint32(offset + 8, true);
  const available = Math.floor((tableEnd - offset - 12) / shape.size);
  if (count > available) issues.push(`WEVT ${kind} definitions are truncated.`);
  return Array.from({ length: Math.min(count, available) }, (_, index) => {
    const base = offset + 12 + index * shape.size;
    const messageId = view.getUint32(base + shape.message, true);
    return {
      kind,
      id: kind === "KEYW" ? `0x${view.getBigUint64(base, true).toString(16)}`
        : String(view.getUint32(base, true)),
      name: readName(bytes, view, view.getUint32(base + shape.name, true), manifestEnd, issues),
      messageId: messageId === 0xffffffff ? null : messageId
    };
  });
};

const readFields = (
  bytes: Uint8Array, view: DataView, offset: number, count: number,
  manifestEnd: number, issues: string[]
): ResourceWevtTemplate["fields"] => {
  // libfwevt section 12.3: each template item descriptor is 20 bytes.
  if (!count) return [];
  if (offset === 0 || !within(offset, count * 20, manifestEnd)) {
    issues.push("WEVT TEMP field descriptors are truncated.");
    return [];
  }
  return Array.from({ length: count }, (_, index) => {
    const base = offset + index * 20;
    return { name: readName(bytes, view, view.getUint32(base + 16, true), manifestEnd, issues),
      inputType: view.getUint8(base + 4), outputType: view.getUint8(base + 5),
      count: view.getUint16(base + 12, true), length: view.getUint16(base + 14, true) };
  });
};

const readTemplates = (
  bytes: Uint8Array, view: DataView, offset: number, tableEnd: number,
  manifestEnd: number, issues: string[]
): ResourceWevtTemplate[] => {
  // libfwevt section 12.1: TEMP has a 40-byte header followed by binary XML and items.
  const count = view.getUint32(offset + 8, true);
  const templates: ResourceWevtTemplate[] = [];
  let cursor = offset + 12;
  for (let index = 0; index < count && within(cursor, 40, tableEnd); index += 1) {
    if (signature(bytes, cursor) !== "TEMP") break;
    const size = view.getUint32(cursor + 4, true);
    if (size < 40 || !within(cursor, size, tableEnd)) break;
    const guid = readGuid(view, cursor + 24);
    if (guid) {
      const itemsOffset = view.getUint32(cursor + 16, true);
      const fragmentEnd = itemsOffset >= cursor + 40 && itemsOffset <= cursor + size
        ? itemsOffset : cursor + size;
      const xmlTree = bytes[cursor + 40] === 0x0f
        ? parseWevtBinXml(bytes, cursor + 40, fragmentEnd, issues) : null;
      templates.push({ offset: cursor, guid, ...(xmlTree ? { xmlTree } : {}),
        fields: readFields(bytes, view, itemsOffset,
          view.getUint32(cursor + 8, true), manifestEnd, issues) });
    }
    cursor += size;
  }
  if (templates.length !== count) issues.push("WEVT TTBL templates are truncated or invalid.");
  return templates;
};

export function parseWevtSection(
  bytes: Uint8Array, offset: number, manifestEnd: number, issues: string[]
): { metadata: ResourceWevtMetadata[]; templates: ResourceWevtTemplate[];
  maps?: ResourceWevtMap[] } {
  const empty = { metadata: [], templates: [] };
  if (!within(offset, 12, manifestEnd) || manifestEnd > bytes.length) {
    issues.push("WEVT section header is truncated.");
    return empty;
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.length);
  const kind = signature(bytes, offset);
  const size = view.getUint32(offset + 4, true);
  // libfwevt sections 5 and 10 allow zero size for empty LEVL and OPCO tables.
  if (size === 0 && ["LEVL", "OPCO"].includes(kind) && view.getUint32(offset + 8, true) === 0) {
    return empty;
  }
  if (size < 12 || !within(offset, size, manifestEnd)) {
    issues.push(`WEVT ${kind} section size is invalid.`);
    return empty;
  }
  const maps = kind === "MAPS" ? parseWevtMaps(bytes, offset, size, manifestEnd, issues) : [];
  return { metadata: readMetadata(bytes, view, offset, offset + size, manifestEnd, kind, issues),
    templates: kind === "TTBL"
      ? readTemplates(bytes, view, offset, offset + size, manifestEnd, issues) : [],
    ...(maps.length ? { maps } : {}) };
}
