"use strict";

export interface RibbonBmlControl {
  kind: string;
  commandId: number | null;
  children: RibbonBmlControl[];
}

// Tree entry codes, control types and ID payloads follow new.ksy.
// https://github.com/DarkShadow44/UIRibbon-Reversing/blob/master/new.ksy
const controlKinds = new Map<number, string>([
  [4, "Context popup"], [5, "Mini toolbar"], [6, "Check box"], [7, "Group"],
  [13, "Spinner"], [15, "Button"], [18, "Split button"], [19, "Application menu"],
  [20, "Drop-down button"], [21, "Gallery"], [24, "Menu group"], [26, "Tab"],
  [27, "Tab group"], [37, "Quick access"], [38, "Subgroup"]
]);

interface Reader {
  bytes: Uint8Array;
  view: DataView;
  cursor: number;
  count: number;
  issues: string[];
  activeExtensions: Set<number>;
}

interface Entry { controls: RibbonBmlControl[]; commandId: number | null }

const within = (reader: Reader, size: number): boolean =>
  size >= 0 && reader.cursor >= 0 && size <= reader.bytes.length - reader.cursor;

const failure = (reader: Reader, description: string): null => {
  reader.issues.push(`Compiled BML control tree ${description}.`);
  return null;
};

const emptyEntry = (): Entry => ({ controls: [], commandId: null });

const readNumber = (reader: Reader): Entry | null => {
  if (!within(reader, 4)) return failure(reader, "property is truncated");
  const size = reader.bytes[reader.cursor + 1];
  const kind = reader.bytes[reader.cursor + 2];
  if (size === 4) {
    if (!within(reader, 8)) return failure(reader, "long property is truncated");
    reader.cursor += 8;
    return emptyEntry();
  }
  if (size !== 1) return failure(reader, "property size is unsupported");
  const flag = reader.bytes[reader.cursor + 3];
  const idSize = flag === 2 ? 4 : flag === 3 ? 2 :
    flag === 4 || flag === 9 || flag === 43 ? 1 : 0;
  if (!idSize) return failure(reader, "property ID encoding is unsupported");
  if (!within(reader, 4 + idSize)) return failure(reader, "property ID is truncated");
  const offset = reader.cursor + 4;
  const commandId = idSize === 4 ? reader.view.getUint32(offset, true) :
    idSize === 2 ? reader.view.getUint16(offset, true) : reader.bytes[offset] ?? 0;
  reader.cursor += 4 + idSize;
  return { controls: [], commandId: kind === 0 ? commandId : null };
};

const readNode = (reader: Reader, depth: number): Entry | null => {
  if (!within(reader, 8)) return failure(reader, "node is truncated");
  const kindCode = reader.view.getUint16(reader.cursor + 2, true);
  const childCount = reader.bytes[reader.cursor + 7] ?? 0;
  reader.cursor += 8;
  const control: RibbonBmlControl = {
    kind: controlKinds.get(kindCode) ?? `Type ${kindCode}`, commandId: null, children: []
  };
  for (let index = 0; index < childCount; index += 1) {
    const child = readEntry(reader, depth + 1);
    if (!child) return null;
    control.children.push(...child.controls);
    if (child.commandId !== null) control.commandId = child.commandId;
  }
  return { controls: [control], commandId: null };
};

const readArray = (reader: Reader, depth: number): Entry | null => {
  if (!within(reader, 5)) return failure(reader, "array is truncated");
  const count = reader.view.getUint16(reader.cursor + 3, true);
  reader.cursor += 5;
  const controls: RibbonBmlControl[] = [];
  for (let index = 0; index < count; index += 1) {
    const child = readEntry(reader, depth + 1);
    if (!child) return null;
    controls.push(...child.controls);
  }
  return { controls, commandId: null };
};

const skipContainer = (reader: Reader): Entry | null => {
  if (!within(reader, 9)) return failure(reader, "command container is truncated");
  const size = reader.view.getUint32(reader.cursor + 1, true);
  if (size < 9 || !within(reader, size)) {
    return failure(reader, "command container size is invalid");
  }
  reader.cursor += size;
  return emptyEntry();
};

const skipSizeInfo = (reader: Reader): Entry | null => {
  if (!within(reader, 2)) return failure(reader, "size entry is truncated");
  const flag = reader.bytes[reader.cursor + 1];
  const size = flag === 2 ? 6 : flag === 3 ? 4 : flag === 9 ? 3 : 0;
  if (!size) return failure(reader, "size entry flag is unsupported");
  if (!within(reader, size)) return failure(reader, "size entry is truncated");
  reader.cursor += size;
  return emptyEntry();
};

const readExtension = (reader: Reader, depth: number): Entry | null => {
  if (!within(reader, 5)) return failure(reader, "extension is truncated");
  const position = reader.view.getUint32(reader.cursor + 1, true);
  const resume = reader.cursor + 5;
  if (position > reader.bytes.length - 2 || reader.activeExtensions.has(position)) {
    return failure(reader, "extension target is invalid or cyclic");
  }
  const size = reader.view.getUint16(position, true);
  if (size < 3 || size > reader.bytes.length - position) {
    return failure(reader, "extension block size is invalid");
  }
  reader.activeExtensions.add(position);
  reader.cursor = position + 2;
  const entry = readEntry(reader, depth + 1);
  const overrun = reader.cursor > position + size;
  reader.activeExtensions.delete(position);
  reader.cursor = resume;
  if (overrun) return failure(reader, "extension block exceeds its declared size");
  return entry;
};

const readEntry = (reader: Reader, depth: number): Entry | null => {
  // The format is recursive; these limits prevent hostile child counts exhausting the stack.
  if (depth > 32 || reader.count++ >= 10000) return failure(reader, "nesting limit is exceeded");
  if (!within(reader, 1)) return failure(reader, "entry is truncated");
  switch (reader.bytes[reader.cursor]) {
    case 1: return readNumber(reader);
    case 22: return readNode(reader, depth);
    case 24: return readArray(reader, depth);
    case 16: return skipContainer(reader);
    case 13:
      if (!within(reader, 7)) return failure(reader, "command extension is truncated");
      reader.cursor += 7;
      return emptyEntry();
    case 62: return readExtension(reader, depth);
    case 59: return skipSizeInfo(reader);
    default: return failure(reader, "entry type is unknown");
  }
};

export const parseRibbonBmlTree = (
  bytes: Uint8Array, start: number, issues: string[]
): RibbonBmlControl | null => {
  if (!Number.isSafeInteger(start) || start < 0 || start > bytes.length) {
    issues.push("Compiled BML control tree offset is invalid.");
    return null;
  }
  const reader: Reader = { bytes, view: new DataView(bytes.buffer, bytes.byteOffset,
    bytes.byteLength), cursor: start, count: 0, issues, activeExtensions: new Set() };
  while (reader.cursor < bytes.length) {
    const entry = readEntry(reader, 0);
    if (!entry) return null;
    if (entry.controls.length) return entry.controls[0] ?? null;
  }
  return null;
};
