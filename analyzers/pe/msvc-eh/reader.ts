import type { EhImage } from "./types.js";

const canonicalEncoding = (first: number, length: number, value: number): boolean => {
  if (length === 5 && first !== 15) return false;
  return length === 1 || value >= 2 ** ((length - 1) * 7);
};

/** Bounded FH4 metadata cursor; invalid reads poison the cursor without throwing. */
export class EhCursor {
  position: number;
  valid = true;
  readonly #end: number;
  readonly #image: EhImage;

  constructor(image: EhImage, rva: number) {
    this.#image = image;
    this.position = rva;
    this.#end = rva + image.available(rva);
  }

  async #read(size: number): Promise<DataView | null> {
    if (!this.valid || this.position + size > this.#end) {
      this.valid = false;
      return null;
    }
    const view = await this.#image.read(this.position, size);
    if (!view) this.valid = false;
    this.position += size;
    return view;
  }

  async byte(): Promise<number> {
    return (await this.#read(1))?.getUint8(0) ?? 0;
  }

  async uint32(): Promise<number> {
    return (await this.#read(4))?.getUint32(0, true) ?? 0;
  }

  async compressed(): Promise<number> {
    const first = await this.byte();
    // MSVC ehdata4_export.h, ReadUnsigned / Compress::getNETencoded.
    // https://devblogs.microsoft.com/cppblog/making-cpp-exception-handling-smaller-x64/
    let length = 1;
    while (length < 5 && (first & (1 << (length - 1)))) length++;
    let value = length === 5 ? 0 : first >>> length;
    for (let index = 1; index < length; index++) {
      value += await this.byte() * 2 ** (length === 5 ? (index - 1) * 8 : index * 8 - length);
    }
    // Fail closed on overlong encodings, including a noncanonical five-byte prefix.
    if (!canonicalEncoding(first, length, value)) this.valid = false;
    return value;
  }

  async count(minimumEntrySize: number): Promise<number> {
    const count = await this.compressed();
    if (!this.valid || count > Math.floor((this.#end - this.position) / minimumEntrySize)) {
      this.valid = false;
      return 0;
    }
    return count;
  }
}
