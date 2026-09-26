import type { SltgReader } from "./sltg-reader.js";

// Wine lookup_code / decode_string: prefix tree nodes 0x80 + big-endian branch offset;
// a leaf contains a marker and a NUL-terminated ANSI word. Words join with spaces.
// https://github.com/wine-mirror/wine/blob/master/dlls/oleaut32/typelib.c
export class SltgHelpStrings {
  private readonly words = new Map<number, string>();
  private readonly table: Uint8Array;
  private readonly maximumLength: number;

  constructor(private readonly reader: SltgReader, offset: number) {
    this.maximumLength = reader.word(offset) ?? 0;
    const size = reader.range(offset + 2, 4) ? reader.view.getUint32(offset + 2, true) : 0;
    this.table = reader.range(offset + 6, size)
      ? reader.data.subarray(offset + 6, offset + 6 + size) : new Uint8Array();
  }

  decode(stream: Uint8Array): string | null {
    if (!stream.length) return null;
    const result: string[] = [];
    const cursor = { bit: 0 };
    let length = 0;
    // Each decoded word consumes input bits or advances the format-declared output length.
    while (cursor.bit < stream.length * 8) {
      const word = this.lookup(stream, cursor);
      if (word === null) return result.join(" ");
      length += word.length + (result.length ? 1 : 0);
      if (length > this.maximumLength) {
        this.reader.warn("TYPELIB SLTG compressed help string exceeds its declared size.");
        return result.join(" ");
      }
      result.push(word);
    }
    return result.join(" ");
  }

  private lookup(stream: Uint8Array, cursor: { bit: number }): string | null {
    const seen = new Set<number>();
    let node = 0;
    while (this.table[node] === 0x80) {
      if (seen.has(node)) {
        this.reader.warn("TYPELIB SLTG compressed help tree contains a cycle.");
        return null;
      }
      seen.add(node);
      if (node + 2 >= this.table.length) {
        this.reader.warn("TYPELIB SLTG compressed help tree node is truncated.");
        return null;
      }
      if (cursor.bit >= stream.length * 8) return null;
      node = ((stream[Math.floor(cursor.bit / 8)] ?? 0) & (0x80 >>> (cursor.bit % 8))) !== 0
        ? node + 3 : this.table[node + 1]! * 256 + this.table[node + 2]!;
      cursor.bit++;
    }
    if (node + 1 >= this.table.length) {
      this.reader.warn("TYPELIB SLTG compressed help tree points outside its table.");
      return null;
    }
    return this.table[node + 1] ? this.word(node) : null;
  }

  private word(node: number): string | null {
    const cached = this.words.get(node);
    if (cached !== undefined) return cached;
    const end = this.table.indexOf(0, node + 1);
    if (end < 0) {
      this.reader.warn("TYPELIB SLTG compressed help word is not terminated.");
      return null;
    }
    const word = this.reader.decoder.decode(this.table.subarray(node + 1, end));
    this.words.set(node, word);
    return word;
  }
}
