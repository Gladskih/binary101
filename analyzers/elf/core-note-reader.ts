import type { ElfCoreField } from "./core-note-types.js";

/** A descriptor-local reader; invalid fields are omitted with a visible notice. */
export class ElfCoreNoteReader {
  readonly issues: string[] = [];
  constructor(readonly bytes: Uint8Array, readonly wordSize: 4 | 8,
    readonly byteOrder: "little" | "big") {
  }
  contains(offset: number, size: number): boolean {
    if (offset >= 0 && size >= 0 && offset + size <= this.bytes.length) return true;
    if (!this.issues.length) this.issues.push("Core note descriptor is truncated.");
    return false;
  }
  unsigned(offset: number, width: number = this.wordSize): bigint {
    if (!this.contains(offset, width)) return 0n;
    let value = 0n;
    for (let index = 0; index < width; index += 1) {
      const position = this.byteOrder === "little" ? offset + width - index - 1 : offset + index;
      value = (value << 8n) | BigInt(this.bytes[position]!);
    }
    return value;
  }
  signed(offset: number, width: number): bigint {
    return BigInt.asIntN(width * 8, this.unsigned(offset, width));
  }
  text(offset: number, width: number): string {
    if (!this.contains(offset, width)) return "";
    return new TextDecoder().decode(this.bytes.subarray(offset, offset + width)).split("\0")[0]!;
  }
  fields(names: string[], offset: number, width: number): ElfCoreField[] {
    return names.flatMap((name, index) => this.contains(offset + index * width, width)
      ? [{ name, value: this.unsigned(offset + index * width, width) }] : []);
  }
}
