"use strict";

import type { ResourcePreviewData } from "./types.js";
import { parseRibbonBmlTree } from "./ribbon-bml-tree.js";

type RibbonBml = NonNullable<ResourcePreviewData["ribbonBml"]>;

// UIRibbon-Reversing/new.ksy, seq and type_strings/type_resource definitions.
// https://github.com/DarkShadow44/UIRibbon-Reversing/blob/master/new.ksy
const resourceKinds = new Map<number, string>([
  [1, "Label title"], [2, "Label description"], [3, "Small high contrast image"],
  [4, "Large high contrast image"], [5, "Small image"], [6, "Large image"],
  [7, "Key tip"], [8, "Tooltip title"], [9, "Tooltip description"]
]);

const within = (offset: number, size: number, end: number): boolean =>
  Number.isSafeInteger(offset) && Number.isSafeInteger(size) && offset >= 0 &&
  size >= 0 && size <= end - offset;

const readStrings = (
  bytes: Uint8Array, view: DataView, start: number, end: number, issues: string[]
): string[] => {
  if (!within(start, 3, end) || bytes[start] !== 1) {
    issues.push("Compiled BML string table is invalid or truncated.");
    return [];
  }
  const strings: string[] = [];
  let cursor = start + 2;
  const count = bytes[start + 1] ?? 0;
  for (let index = 0; index < count; index += 1) {
    if (!within(cursor, 3, end) || bytes[cursor] !== 1) {
      issues.push("Compiled BML string entry is invalid or truncated.");
      return strings;
    }
    const length = view.getUint16(cursor + 1, true);
    cursor += 3;
    if (!within(cursor, length, end)) {
      issues.push("Compiled BML string is truncated.");
      return strings;
    }
    strings.push(new TextDecoder("windows-1252").decode(bytes.subarray(cursor, cursor + length)));
    cursor += length;
  }
  if (cursor + 1 !== end) issues.push("Compiled BML string table size is inconsistent.");
  return strings;
};

const readCommands = (
  bytes: Uint8Array, view: DataView, start: number, issues: string[]
): { commands: RibbonBml["commands"]; end: number } => {
  if (!within(start, 4, bytes.length)) {
    issues.push("Compiled BML command table is truncated.");
    return { commands: [], end: bytes.length };
  }
  const count = view.getUint32(start, true);
  const commands: RibbonBml["commands"] = [];
  let cursor = start + 4;
  for (let index = 0; index < count; index += 1) {
    if (!within(cursor, 5, bytes.length)) {
      issues.push("Compiled BML command record is truncated.");
      return { commands, end: bytes.length };
    }
    const id = view.getUint32(cursor, true);
    const resourceCount = bytes[cursor + 4] ?? 0;
    cursor += 5;
    const resources: RibbonBml["commands"][number]["resources"] = [];
    for (let item = 0; item < resourceCount; item += 1) {
      if (!within(cursor, 5, bytes.length)) {
        issues.push("Compiled BML command resource is truncated.");
        return { commands, end: bytes.length };
      }
      const type = bytes[cursor] ?? 0;
      const resourceId = view.getUint32(cursor + 1, true);
      cursor += 5;
      const kind = resourceKinds.get(type) ?? `Type ${type}`;
      if (type >= 3 && type <= 6) {
        if (!within(cursor, 2, bytes.length)) {
          issues.push("Compiled BML image DPI is truncated.");
          return { commands, end: bytes.length };
        }
        resources.push({ kind, resourceId, minimumDpi: view.getUint16(cursor, true) });
        cursor += 2;
      } else resources.push({ kind, resourceId });
    }
    commands.push({ id, resources });
  }
  return { commands, end: cursor };
};

export const parseRibbonBml = (
  bytes: Uint8Array, issues: string[]
): RibbonBml | null => {
  // new.ksy: 9-byte prefix, "SCBin", LE file length, marker 2, string-section length.
  if (!within(0, 23, bytes.length) ||
    ![0, 18, 0, 0, 0, 0, 0, 1, 0, 83, 67, 66, 105, 110]
      .every((byte, index) => bytes[index] === byte)) {
    issues.push("Compiled BML header is invalid or truncated.");
    return null;
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.length);
  if (view.getUint32(14, true) !== bytes.length) {
    issues.push("Compiled BML declared length differs from resource size.");
  }
  if (bytes[18] !== 2) issues.push("Compiled BML string-section marker is unknown.");
  const size = view.getUint32(19, true);
  if (size < 7 || !within(19, size, bytes.length)) {
    issues.push("Compiled BML string-section length is invalid.");
    return { strings: [], commands: [] };
  }
  const end = 19 + size;
  const { commands, end: treeStart } = readCommands(bytes, view, end, issues);
  const tree = treeStart < bytes.length ? parseRibbonBmlTree(bytes, treeStart, issues) : null;
  return { strings: readStrings(bytes, view, 23, end, issues),
    commands, ...(tree ? { tree } : {}) };
};
