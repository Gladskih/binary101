// Delphi/FPC TPF0, TValueType and TBinaryObjectReader. No classes are instantiated.
// https://github.com/fpc/FPCSource/blob/main/rtl/objpas/classes/reader.inc
// https://github.com/fpc/FPCSource/blob/main/rtl/objpas/classes/classesh.inc
export type DfmValue =
  | { kind: "null" }
  | { kind: "string" | "identifier" | "number" | "extended"; value: string }
  | { kind: "boolean"; value: boolean }
  | { kind: "binary"; data: Uint8Array }
  | { kind: "set"; values: string[] }
  | { kind: "list"; values: DfmValue[] }
  | { kind: "collection"; items: DfmProperty[][] };
export interface DfmProperty { name: string; value: DfmValue }

export class DfmReader {
  offset = 4;
  constructor(readonly bytes: Uint8Array) {}
  read(size: number): Uint8Array {
    if (!Number.isSafeInteger(this.offset) || this.offset < 0 || this.offset > this.bytes.length ||
      !Number.isSafeInteger(size) || size < 0 || size > this.bytes.length - this.offset) {
      throw new Error(`DFM payload is truncated at offset ${this.offset} (${size} bytes required).`);
    }
    const result = this.bytes.subarray(this.offset, this.offset + size);
    this.offset += size;
    return result;
  }
  peek(): number {
    if (!Number.isSafeInteger(this.offset) || this.offset < 0 || this.offset >= this.bytes.length) {
      throw new Error(`DFM terminator is missing at offset ${this.offset}.`);
    }
    return this.bytes[this.offset]!;
  }
  byte(): number { return this.read(1)[0]!; }
  unsigned(): number {
    const data = this.read(4);
    return new DataView(data.buffer, data.byteOffset, 4).getUint32(0, true);
  }
  shortString(): string {
    return new TextDecoder("windows-1252").decode(this.read(this.byte()));
  }
}

const numericValue = (reader: DfmReader, tag: number): DfmValue => {
  const size = new Map([[2, 1], [3, 2], [4, 4], [5, 10], [15, 4], [16, 8],
    [17, 8], [19, 8], [22, 8], [23, 8]]).get(tag)!;
  const data = reader.read(size);
  const view = new DataView(data.buffer, data.byteOffset, size);
  if (tag === 5) return { kind: "extended", value: Array.from(data, byte =>
    byte.toString(16).padStart(2, "0")).join("") }; // Preserve x87 80-bit precision.
  if (tag === 16) return { kind: "number", value: `${view.getBigInt64(0, true)} / 10000` };
  const value = tag === 2 ? view.getInt8(0) : tag === 3 ? view.getInt16(0, true)
    : tag === 4 ? view.getInt32(0, true) : tag === 15 ? view.getFloat32(0, true)
      : tag === 19 ? view.getBigInt64(0, true) : tag === 22 ? view.getBigUint64(0, true)
        : view.getFloat64(0, true);
  return { kind: "number", value: String(value) };
};

const stringValue = (reader: DfmReader, tag: number): DfmValue => {
    const length = reader.unsigned();
    const wide = tag === 18 || tag === 21;
    return { kind: "string", value: new TextDecoder(wide ? "utf-16le"
      : tag === 20 ? "utf-8" : "windows-1252").decode(reader.read(length * (wide ? 2 : 1))) };
};

const setValue = (reader: DfmReader): DfmValue => {
    const values: string[] = [];
    for (let name = reader.shortString(); name; name = reader.shortString()) values.push(name);
    return { kind: "set", values };
};

const scalarValue = (reader: DfmReader, tag: number): DfmValue => {
  if ([0, 13].includes(tag)) return { kind: "null" };
  if ([8, 9].includes(tag)) return { kind: "boolean", value: tag === 9 };
  if ([6, 7].includes(tag)) return { kind: tag === 7 ? "identifier" : "string", value: reader.shortString() };
  if ([2, 3, 4, 5, 15, 16, 17, 19, 22, 23].includes(tag)) return numericValue(reader, tag);
  if (tag === 10) return { kind: "binary", data: reader.read(reader.unsigned()) };
  if ([12, 18, 20, 21].includes(tag)) return stringValue(reader, tag);
  if (tag === 11) return setValue(reader);
  throw new Error(`DFM value type ${tag} at offset ${reader.offset - 1} is unsupported; remaining bytes preserved.`);
};

type ValueTask = { kind: "value"; assign: (value: DfmValue) => void }
  | { kind: "list"; values: DfmValue[] }
  | { kind: "collection"; items: DfmProperty[][] }
  | { kind: "properties"; properties: DfmProperty[] };

const collectionItem = (reader: DfmReader): void => {
  // Optional integer order precedes the vaList marker in a collection item.
  if ([2, 3, 4].includes(reader.peek())) scalarValue(reader, reader.byte());
  if (reader.byte() !== 1) throw new Error(`DFM collection item marker is invalid at offset ${reader.offset - 1}.`);
};

const assignBinaryValue = (reader: DfmReader, task: Extract<ValueTask, {kind: "value"}>,
  tasks: ValueTask[]): void => {
      const tag = reader.byte();
      if (tag === 1) {
        const values: DfmValue[] = [];
        task.assign({ kind: "list", values }); tasks.push({ kind: "list", values });
      } else if (tag === 14) {
        const items: DfmProperty[][] = [];
        task.assign({ kind: "collection", items }); tasks.push({ kind: "collection", items });
      } else task.assign(scalarValue(reader, tag));
};

export const readDfmValue = (reader: DfmReader): DfmValue => {
  let result: DfmValue = { kind: "null" };
  const tasks: ValueTask[] = [{ kind: "value", assign: value => { result = value; } }];
  while (tasks.length) {
    const task = tasks.pop()!;
    if (task.kind === "list" || task.kind === "collection") {
      if (reader.peek() === 0) { reader.byte(); continue; }
      tasks.push(task);
      if (task.kind === "list") tasks.push({ kind: "value", assign: value => { task.values.push(value); } });
      else {
        collectionItem(reader);
        const properties: DfmProperty[] = [];
        task.items.push(properties);
        tasks.push({ kind: "properties", properties });
      }
    } else if (task.kind === "properties") {
      const name = reader.shortString();
      if (name) tasks.push(task, { kind: "value", assign: value => { task.properties.push({ name, value }); } });
    } else {
      assignBinaryValue(reader, task, tasks);
    }
  }
  return result;
};
