"use strict";

export interface RibbonBmlControl {
  kind: string;
  commandId: number | null;
  children: RibbonBmlControl[];
  reference?: number;
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
  extensions: Map<number, Entry>;
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

const readPropertyId = (reader: Reader, idSize: number, kind: number): Entry => {
  const offset = reader.cursor + 4;
  const commandId = idSize === 4 ? reader.view.getUint32(offset, true) :
    idSize === 2 ? reader.view.getUint16(offset, true) : reader.bytes[offset] ?? 0;
  reader.cursor += 4 + idSize;
  return { controls: [], commandId: kind === 0 ? commandId : null };
};

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
  const idSize = new Map([[2, 4], [3, 2], [4, 1], [9, 1], [43, 1]]).get(flag ?? -1) ?? 0;
  if (!idSize) return failure(reader, "property ID encoding is unsupported");
  if (!within(reader, 4 + idSize)) return failure(reader, "property ID is truncated");
  return readPropertyId(reader, idSize, kind!);
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

type TreeTask = { kind: "entry"; assign: (entry: Entry) => void }
  | { kind: "complete"; entry: Entry; assign: (entry: Entry) => void }
  | { kind: "children"; remaining: number; entry: Entry; control?: RibbonBmlControl }
  | { kind: "extension"; position: number; resume: number; end: number;
    assign: (entry: Entry) => void; entry: Entry | null };

const beginExtension = (reader: Reader, task: Extract<TreeTask, { kind: "entry" }>, tasks: TreeTask[]): boolean => {
  if (!within(reader, 5)) { failure(reader, "extension is truncated"); return false; }
  const position = reader.view.getUint32(reader.cursor + 1, true);
  const resume = reader.cursor + 5;
  if (position > reader.bytes.length - 2 || reader.activeExtensions.has(position)) {
    failure(reader, "extension target is invalid or cyclic"); return false;
  }
  const size = reader.view.getUint16(position, true);
  if (size < 3 || size > reader.bytes.length - position) {
    failure(reader, "extension block size is invalid"); return false;
  }
  const cached = reader.extensions.get(position);
  if (cached) {
    reader.cursor = resume;
    // Preserve the shared block identity instead of expanding a compressed DAG into a tree.
    task.assign({ commandId: cached.commandId, controls: [{ kind: "Shared block",
      commandId: null, children: [], reference: position }] });
    return true;
  }
  reader.activeExtensions.add(position);
  reader.cursor = position + 2;
  const extension: Extract<TreeTask, { kind: "extension" }> = { kind: "extension", position,
    resume, end: position + size, assign: task.assign, entry: null };
  tasks.push(extension, { kind: "entry", assign: entry => { extension.entry = entry; } });
  return true;
};

const readControlHeader = (reader: Reader): RibbonBmlControl => {
  return {
    kind: controlKinds.get(reader.view.getUint16(reader.cursor + 2, true)) ??
      `Type ${reader.view.getUint16(reader.cursor + 2, true)}`,
    commandId: null, children: [] };
};

const beginContainer = (reader: Reader, task: Extract<TreeTask, { kind: "entry" }>, tasks: TreeTask[]): boolean => {
  const node = reader.bytes[reader.cursor] === 22;
  if (!within(reader, node ? 8 : 5)) { failure(reader, node ? "node is truncated" : "array is truncated"); return false; }
  const control = node ? readControlHeader(reader) : undefined;
  const remaining = node ? reader.bytes[reader.cursor + 7]! : reader.view.getUint16(reader.cursor + 3, true);
  reader.cursor += node ? 8 : 5;
  const entry: Entry = { controls: control ? [control] : [], commandId: null };
  tasks.push({ kind: "complete", entry, assign: task.assign },
    { kind: "children", remaining, entry, ...(control ? { control } : {}) });
  return true;
};

const readPrimitive = (reader: Reader): Entry | null => {
  switch (reader.bytes[reader.cursor]) {
    case 1: return readNumber(reader);
    case 16: return skipContainer(reader);
    case 13:
      if (!within(reader, 7)) return failure(reader, "command extension is truncated");
      reader.cursor += 7; return emptyEntry();
    case 59: return skipSizeInfo(reader);
    default: return failure(reader, "entry type is unknown");
  }
};

const readEntryTask = (reader: Reader, task: Extract<TreeTask, { kind: "entry" }>,
  tasks: TreeTask[]): boolean => {
      if (!within(reader, 1)) return Boolean(failure(reader, "entry is truncated"));
      const type = reader.bytes[reader.cursor];
      if (type === 22 || type === 24) { if (!beginContainer(reader, task, tasks)) return false; }
      else if (type === 62) { if (!beginExtension(reader, task, tasks)) return false; }
      else {
        const entry = readPrimitive(reader);
        if (!entry) return false;
        task.assign(entry);
      }
  return true;
};

const readEntry = (reader: Reader): Entry | null => {
  let result: Entry | null = null;
  const tasks: TreeTask[] = [{ kind: "entry", assign: entry => { result = entry; } }];
  while (tasks.length) {
    const task = tasks.pop()!;
    if (task.kind === "complete") task.assign(task.entry);
    else if (task.kind === "extension") {
      reader.activeExtensions.delete(task.position);
      const overrun = reader.cursor > task.end;
      reader.cursor = task.resume;
      if (overrun || !task.entry) return failure(reader, "extension block exceeds its declared size");
      reader.extensions.set(task.position, task.entry); task.assign(task.entry);
    } else if (task.kind === "children") {
      if (!task.remaining) continue;
      task.remaining -= 1;
      tasks.push(task, { kind: "entry", assign: child => {
        const controls = task.control?.children ?? task.entry.controls;
        for (const control of child.controls) controls.push(control);
        if (task.control && child.commandId !== null) task.control.commandId = child.commandId;
      } });
    } else if (!readEntryTask(reader, task, tasks)) return null;
  }
  return result;
};

export const parseRibbonBmlTree = (
  bytes: Uint8Array, start: number, issues: string[]
): RibbonBmlControl | null => {
  if (!Number.isSafeInteger(start) || start < 0 || start > bytes.length) {
    issues.push("Compiled BML control tree offset is invalid.");
    return null;
  }
  const reader: Reader = { bytes, view: new DataView(bytes.buffer, bytes.byteOffset,
    bytes.byteLength), cursor: start, extensions: new Map(), issues, activeExtensions: new Set() };
  while (reader.cursor < bytes.length) {
    const entry = readEntry(reader);
    if (!entry) return null;
    if (entry.controls.length) return entry.controls[0] ?? null;
  }
  return null;
};
