import {
  NativeFormatError, type NativeFormatHandle, type NativeFormatReader
} from "./native-format-reader.js";
import { nativeFormatSchemas, type NativeFormatField } from "./native-format-schema.js";

type RecordValue = number | Uint8Array | NativeFormatHandle | NativeFormatHandle[] | number[];

// HandleType is the contiguous range 1..63 in NativeFormatReaderCommonGen.cs.
const handleTypes = Array.from({ length: 63 }, (_, index) => index + 1);

export class NativeFormatRecord {
  readonly values: Record<string, RecordValue> = {};
  failure?: unknown;

  #value(name: string): RecordValue {
    const value = this.values[name];
    if (value === undefined) throw new NativeFormatError(`Record field ${name} could not be read.`);
    return value;
  }

  number(name: string): number {
    return this.#value(name) as number;
  }

  handle(name: string): NativeFormatHandle {
    return this.#value(name) as NativeFormatHandle;
  }

  handles(name: string): NativeFormatHandle[] {
    return this.#value(name) as NativeFormatHandle[];
  }

  numbers(name: string): number[] {
    return this.#value(name) as number[];
  }
}

export class NativeFormatStore {
  readonly #records = new Map<string, NativeFormatRecord>();

  constructor(readonly reader: NativeFormatReader, readonly warnings: Set<string>) {}

  record(handle: NativeFormatHandle): NativeFormatRecord {
    const key = `${handle.type}:${handle.offset}`;
    const cached = this.#records.get(key);
    if (cached) return cached;
    const record = new NativeFormatRecord();
    this.#records.set(key, record);
    let fieldName = "layout";
    try {
      const fields = nativeFormatSchemas[handle.type];
      if (!fields) throw new NativeFormatError(`Unsupported record type ${handle.type}.`);
      let offset = handle.offset;
      for (const field of fields) {
        fieldName = field[0];
        offset = this.#readField(record, field, offset);
      }
    } catch (error) {
      record.failure = error;
      const kind = ({ 0x23: "field", 0x28: "method", 0x3a: "type" } as Record<number, string>)[
        handle.type] ?? `record ${handle.type}`;
      this.warnings.add(`NativeFormat ${kind} at 0x${handle.offset.toString(16)} (${fieldName}): ` +
        `${error instanceof Error ? error.message : "decoding failed"}`);
    }
    return record;
  }

  #readField(record: NativeFormatRecord, field: NativeFormatField, offset: number): number {
    const [name, encoding, type] = field;
    if (encoding === "handles" || encoding === "unsigneds" || encoding === "signeds") {
      return this.#readCollection(record, field, offset);
    }
    if (encoding === "handle") {
      const decoded = this.reader.handle(offset, type ? [type] : handleTypes);
      record.values[name] = decoded.value;
      return decoded.nextOffset;
    }
    const decoded = encoding === "bytes" ? this.reader.bytes(offset) :
      encoding === "byte" ? this.reader.uint8(offset) : this.reader.unsigned(offset);
    record.values[name] = decoded.value;
    return decoded.nextOffset;
  }

  #readCollection(record: NativeFormatRecord, field: NativeFormatField, offset: number): number {
    const [name, encoding, type] = field;
    const count = this.reader.collectionCount(offset);
    let nextOffset = count.nextOffset;
    const values: (NativeFormatHandle | number)[] = [];
    // Preserve successfully read elements when a later element is malformed.
    record.values[name] = values as NativeFormatHandle[] | number[];
    for (let index = 0; index < count.value; index += 1) {
      const decoded = encoding === "handles" ?
        this.reader.handle(nextOffset, type ? [type] : handleTypes) :
        encoding === "signeds" ? this.reader.signed(nextOffset) : this.reader.unsigned(nextOffset);
      if (typeof decoded.value === "number" || decoded.value.offset) values.push(decoded.value);
      nextOffset = decoded.nextOffset;
    }
    return nextOffset;
  }
}
