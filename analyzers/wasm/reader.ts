import type { WasmStream } from "./stream.js";

// Integer and UTF-8 constraints: https://webassembly.github.io/spec/core/binary/values.html
export class WasmReader {
  constructor(readonly stream: WasmStream, readonly end = stream.size) {}
  get remaining(): number { return this.end - this.stream.position; }
  get offset(): number { return this.stream.position; }
  async take(size: number): Promise<Uint8Array> {
    this.check(size);
    return this.stream.read(size);
  }
  check(size: number): void {
    if (!Number.isSafeInteger(size)) throw new Error(`Invalid byte count ${size}`);
    if (size < 0 || size > this.remaining) throw new Error(`Truncated data at ${this.offset}`);
  }
  async skip(size: number): Promise<void> {
    this.check(size);
    await this.stream.consume(size);
  }
  async byte(): Promise<number> { this.check(1); return this.stream.byte(); }
  async unsigned(bits = 32): Promise<bigint> {
    let value = 0n;
    for (let shift = 0; shift < bits; shift += 7) {
      const byte = await this.byte();
      value |= BigInt(byte & 0x7f) << BigInt(shift);
      if (!(byte & 0x80)) {
        if (value >= (1n << BigInt(bits))) throw new Error(`LEB128 u${bits} overflow`);
        return value;
      }
    }
    throw new Error(`LEB128 u${bits} is too long`);
  }
  async u32(): Promise<number> { return Number(await this.unsigned()); }
  async signed(bits: number): Promise<bigint> {
    let value = 0n;
    for (let shift = 0; shift < bits; shift += 7) {
      const byte = await this.byte();
      value |= BigInt(byte & 0x7f) << BigInt(shift);
      if (!(byte & 0x80)) {
        const signed = byte & 0x40 ? value - (1n << BigInt(shift + 7)) : value;
        if (signed !== BigInt.asIntN(bits, signed)) throw new Error(`LEB128 s${bits} overflow`);
        return signed;
      }
    }
    throw new Error(`LEB128 s${bits} is too long`);
  }
  async count(): Promise<number> {
    const count = await this.u32();
    if (count > this.remaining) throw new Error("Truncated vector");
    return count;
  }
  async name(): Promise<string> {
    const size = await this.u32();
    this.check(size);
    // WASM names preserve U+FEFF; suppress the decoder's BOM-stripping behavior.
    // https://encoding.spec.whatwg.org/#dom-textdecoder-ignorebom
    const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
    const parts: string[] = [];
    let remaining = size;
    while (remaining) {
      // The read window bounds temporary I/O memory, not accepted name length.
      const bytes = await this.take(Math.min(remaining, 64 * 1024));
      parts.push(decoder.decode(bytes, { stream: true }));
      remaining -= bytes.length;
    }
    parts.push(decoder.decode());
    return parts.join("");
  }
  async vector<Value>(read: () => Promise<Value>, values: Value[] = []): Promise<Value[]> {
    const count = await this.count();
    for (let index = 0; index < count; index++) values.push(await read());
    return values;
  }
  child(size: number): WasmReader {
    this.check(size);
    return new WasmReader(this.stream, this.offset + size);
  }
  finish(): void {
    if (this.remaining) throw new Error(`${this.remaining} trailing byte(s) at ${this.offset}`);
  }
}
