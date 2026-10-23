import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";
import { readHllName } from "./hll-strings.js";

// IBM HLL "Field ID Values". Unlike C6, 0x8b is an unsigned byte.
// https://www.os2site.com/sw/dev/openwatcom/docs/ibmhll.htm
export class HllTypeFields {
  offset = 0;
  constructor(readonly reader: LegacyCodeViewReader) {}
  async byte(): Promise<number> { return (await this.reader.view(this.offset++, 1)).getUint8(0); }
  async skip(size: number): Promise<void> { await this.reader.view(this.offset, size); this.offset += size; }
  async index(): Promise<void> {
    if (await this.byte() !== 0x83) throw new Error("Invalid HLL type index field.");
    await this.skip(2);
  }
  async span(): Promise<number> {
    const code = await this.byte();
    const size = new Map([[0x85, 2], [0x86, 4], [0x88, 1], [0x89, 2], [0x8a, 4], [0x8b, 1]]).get(code);
    if (size === undefined) throw new Error(`Unknown HLL numeric field ${code}.`);
    const view = await this.reader.view(this.offset, size);
    this.offset += size;
    let value = 0;
    for (let index = size - 1; index >= 0; index--) value = value * 256 + view.getUint8(index);
    return code >= 0x88 && code <= 0x8a && view.getUint8(size - 1) & 128 ? value - 2 ** (size * 8) : value;
  }
  async string(): Promise<string> {
    if (await this.byte() !== 0x82) throw new Error("Invalid HLL string field.");
    return this.pascal();
  }
  async pascal(): Promise<string> {
    const value = await this.reader.pascal(this.offset);
    this.offset = value.end;
    return value.name;
  }
  async name(): Promise<string> {
    const value = await readHllName(this.reader, this.offset);
    this.offset = value.end;
    return value.name;
  }
}
