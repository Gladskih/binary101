import { NativeFormatError, NativeFormatReader } from "./native-format-reader.js";

type NativeArrayStep = { kind: "branch" | "leaf"; offset: number } | { kind: "absent" };

// Block size, index widths and tree flags follow the upstream NativeArray reader.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.Reflection.ReadyToRun/NativeArray.cs
export class NativeArrayReader {
  readonly #reader: NativeFormatReader;
  readonly #view: DataView;
  readonly #base: number;
  readonly #width: number;
  readonly #nodes = new Map<number,
    { value: number; nextOffset: number } | { error: unknown }>();
  readonly count: number;

  constructor(bytes: Uint8Array) {
    this.#reader = new NativeFormatReader(bytes);
    this.#view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const header = this.#reader.unsigned(0);
    this.count = header.value >>> 2;
    this.#base = header.nextOffset;
    this.#width = (header.value & 3) === 0 ? 1 : (header.value & 3) === 1 ? 2 : 4;
    if (Math.ceil(this.count / 16) * this.#width > bytes.length - this.#base) {
      throw new NativeFormatError("NativeArray block index is truncated.");
    }
  }

  #node(offset: number): { value: number; nextOffset: number } {
    const cached = this.#nodes.get(offset);
    if (cached) {
      if ("error" in cached) throw cached.error;
      return cached;
    }
    try {
      const node = this.#reader.unsigned(offset);
      this.#nodes.set(offset, node);
      return node;
    } catch (error) {
      this.#nodes.set(offset, { error });
      throw error;
    }
  }

  #blockOffset(index: number): number {
    const offset = this.#base + Math.floor(index / 16) * this.#width;
    if (this.#width === 1) return this.#base + this.#view.getUint8(offset);
    if (this.#width === 2) return this.#base + this.#view.getUint16(offset, true);
    return this.#base + this.#view.getUint32(offset, true);
  }

  at(index: number): number | null {
    if (!Number.isSafeInteger(index) || index < 0 || index >= this.count) return null;
    let offset = this.#blockOffset(index);
    for (let bit = 8; bit > 0; bit >>>= 1) {
      const step = this.#step(index, bit, offset);
      if (step.kind === "absent") return null;
      if (step.kind === "leaf") return this.#requireEntry(step.offset);
      offset = step.offset;
    }
    return this.#requireEntry(offset);
  }

  #step(index: number, bit: number, offset: number): NativeArrayStep {
    const node = this.#node(offset);
    if ((index & bit) !== 0 && (node.value & 2) !== 0) {
      return { kind: "branch", offset: offset + (node.value >>> 2) };
    }
    if ((index & bit) === 0 && (node.value & 1) !== 0) {
      return { kind: "branch", offset: node.nextOffset };
    }
    return (node.value & 3) === 0 && (node.value >>> 2) === (index & 15)
      ? { kind: "leaf", offset: node.nextOffset } : { kind: "absent" };
  }

  #requireEntry(offset: number): number {
    if (offset >= this.#view.byteLength) {
      throw new NativeFormatError("NativeArray entry is outside the section.");
    }
    return offset;
  }
}
