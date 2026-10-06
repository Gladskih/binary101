import type { NativeFormatReader } from "./native-format-reader.js";

export class NativeFormatCursor {
  readonly #decoder = new TextDecoder("utf-8", { fatal: true });
  constructor(readonly reader: NativeFormatReader, public offset: number) {}
  unsigned(): number {
    const field = this.reader.unsigned(this.offset);
    this.offset = field.nextOffset;
    return field.value;
  }
  count(): number {
    const count = this.unsigned();
    if (count > this.reader.size - this.offset) throw new Error("NativeFormat count exceeds remaining bytes.");
    return count;
  }
  indices(): number[] {
    const count = this.count();
    const indices: number[] = [];
    for (let index = 0; index < count; index += 1) indices.push(this.unsigned());
    return indices;
  }
  string(): string {
    const field = this.reader.bytes(this.offset);
    this.offset = field.nextOffset;
    return this.#decoder.decode(field.value);
  }
  fork(offset: number): NativeFormatCursor { return new NativeFormatCursor(this.reader, offset); }
}
