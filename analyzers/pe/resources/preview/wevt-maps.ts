"use strict";

import type { ResourceWevtMap } from "./types.js";

// libfwevt sections 6, 6.2 and 6.3 describe MAPS, VMAP entries and map strings.
// BMAP entries are explicitly undocumented in section 6.1.
// https://github.com/libyal/libfwevt/blob/main/documentation/Windows%20Event%20manifest%20binary%20format.asciidoc
const within = (offset: number, size: number, end: number): boolean =>
  Number.isSafeInteger(offset) && Number.isSafeInteger(size) &&
  offset >= 0 && size >= 0 && size <= end - offset;

const signature = (bytes: Uint8Array, offset: number): string =>
  String.fromCharCode(...bytes.subarray(offset, offset + 4));

const readMapName = (
  bytes: Uint8Array, view: DataView, offset: number, end: number, issues: string[]
): string | null => {
  if (offset === 0) return null;
  if (!within(offset, 4, end)) {
    issues.push("WEVT map name offset is invalid.");
    return null;
  }
  const size = view.getUint32(offset, true);
  if (size < 6 || size % 2 || !within(offset, size, end)) {
    issues.push("WEVT map name is invalid or truncated.");
    return null;
  }
  return new TextDecoder("utf-16le").decode(bytes.subarray(offset + 4, offset + size))
    .replace(/\0.*/su, "");
};

const readValueMap = (
  bytes: Uint8Array, view: DataView, offset: number, sectionEnd: number,
  manifestEnd: number, issues: string[]
): ResourceWevtMap | null => {
  if (!within(offset, 16, sectionEnd)) {
    issues.push("WEVT VMAP header is truncated.");
    return null;
  }
  const size = view.getUint32(offset + 4, true);
  if (size < 16 || !within(offset, size, sectionEnd)) {
    issues.push("WEVT VMAP size is invalid.");
    return null;
  }
  const count = view.getUint32(offset + 12, true);
  const available = Math.floor((size - 16) / 8);
  if (count > available) issues.push("WEVT VMAP entries are truncated.");
  return { offset, kind: "VMAP",
    name: readMapName(bytes, view, view.getUint32(offset + 8, true), manifestEnd, issues),
    entries: Array.from({ length: Math.min(count, available) }, (_, index) => {
      const entry = offset + 16 + index * 8;
      const messageId = view.getUint32(entry + 4, true);
      return { value: view.getUint32(entry, true),
        messageId: messageId === 0xffffffff ? null : messageId };
    }) };
};

export const parseWevtMaps = (
  bytes: Uint8Array, offset: number, size: number, manifestEnd: number, issues: string[]
): ResourceWevtMap[] => {
  if (!within(offset, 12, manifestEnd) || !within(offset, size, manifestEnd) ||
    size < 12 || manifestEnd > bytes.length) {
    issues.push("WEVT MAPS section is invalid or truncated.");
    return [];
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.length);
  const count = view.getUint32(offset + 8, true);
  if (count === 0) return [];
  // MAPS stores offsets for maps 2..N; map 1 starts after that offset array.
  if ((count - 1) * 4 > size - 12) {
    issues.push("WEVT MAPS definition offsets are truncated.");
    return [];
  }
  const sectionEnd = offset + size;
  const explicitFirst = offset + 12 + count * 4;
  // wevtsvc.dll has one absolute offset per map; libfwevt describes N-1 offsets.
  const fullDirectory = count * 4 <= size - 12 && within(explicitFirst, 4, sectionEnd) &&
    ["VMAP", "BMAP"].includes(signature(bytes, explicitFirst));
  const first = fullDirectory ? explicitFirst : offset + 12 + (count - 1) * 4;
  const offsets = Array.from({ length: count }, (_, index) => fullDirectory
    ? view.getUint32(offset + 12 + index * 4, true)
    : index === 0 ? first : view.getUint32(offset + 12 + (index - 1) * 4, true));
  const maps: ResourceWevtMap[] = [];
  for (const mapOffset of offsets.sort((left, right) => left - right)) {
    if (mapOffset < first || !within(mapOffset, 4, sectionEnd)) {
      issues.push("WEVT map definition offset is invalid.");
      continue;
    }
    const kind = signature(bytes, mapOffset);
    if (kind === "VMAP") {
      const map = readValueMap(bytes, view, mapOffset, sectionEnd, manifestEnd, issues);
      if (map) maps.push(map);
    } else if (kind === "BMAP") {
      issues.push("WEVT BMAP entry layout is not documented.");
      maps.push({ offset: mapOffset, kind: "BMAP", name: null, entries: [] });
    } else issues.push("WEVT map definition signature is unknown.");
  }
  return maps;
};
