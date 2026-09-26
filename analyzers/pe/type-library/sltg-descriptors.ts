import { variantTypeName } from "./descriptors.js";
import type { SltgReader } from "./sltg-reader.js";

// SLTG_DoElem / SLTG_DoType: modifier bits and a sequential WORD type expression.
// https://github.com/wine-mirror/wine/blob/master/dlls/oleaut32/typelib.c
const parameterFlags = (first: number): number => {
  return ((first & 0xc000) === 0xc000 ? 0 : first & 0x8000 ? 3 : first & 0x4000 ? 2 : 1)
    | (first & 0x2000 ? 4 : 0) | (first & 0x80 ? 8 : 0);
};

class SltgTypeExpression {
  private readonly wrappers: Array<(type: string) => string> = [];

  constructor(private readonly reader: SltgReader, private cursor: number) {}

  read(): { type: string; flags: number; next: number } {
    const flags = parameterFlags(this.reader.word(this.cursor) ?? 0);
    while (this.cursor < this.reader.data.length) {
      const code = this.reader.word(this.cursor);
      if (code === null) break;
      this.cursor += 2;
      if ((code & 0xe00) === 0xe00) this.wrappers.push(type => `${type}*`);
      const type = this.step(code & 0x3f);
      if (type !== null) return {
        type: this.wrappers.reduceRight((value, wrap) => wrap(value), type), flags, next: this.cursor
      };
    }
    this.reader.warn("TYPELIB SLTG type expression is truncated.");
    return { type: "invalid type", flags, next: this.cursor };
  }

  private step(kind: number): string | null {
    switch (kind) {
      case 26: this.wrappers.push(type => `${type}*`); return null;
      case 27: this.cursor += 2; this.wrappers.push(type => `SAFEARRAY(${type})`); return null;
      case 28: {
        const bounds = readBounds(this.reader, this.reader.word(this.cursor) ?? -1);
        this.cursor += 2;
        this.wrappers.push(type => `${type}${bounds}`);
        return null;
      }
      case 29: {
        const reference = this.reader.references.get((this.reader.word(this.cursor) ?? 0) / 4);
        this.cursor += 2;
        if (reference === undefined) this.reader.warn("TYPELIB SLTG user-defined type reference is invalid.");
        return `href(${reference ?? -1})`;
      }
      default: return variantTypeName(kind);
    }
  }
}

export const readSltgType = (
  reader: SltgReader, offset: number
): { type: string; flags: number; next: number } => new SltgTypeExpression(reader, offset).read();

const readBounds = (reader: SltgReader, offset: number): string => {
  const dimensions = reader.word(offset);
  if (!dimensions || !reader.range(offset, 16 + dimensions * 8)) {
    reader.warn("TYPELIB SLTG array bounds are invalid.");
    return "[invalid bounds]";
  }
  return Array.from({ length: dimensions }, (_, index) => {
    const bound = offset + 16 + index * 8;
    const lower = reader.view.getInt32(bound + 4, true);
    return `[${lower}..${lower + reader.view.getUint32(bound, true) - 1}]`;
  }).join("");
};
