import type { NativeAotFunctionReferences } from "./function-references.js";
import type { NativeAotRuntimeType } from "./runtime-type-map.js";

export type NativeAotGcDescriptor =
  | { kind: "object"; series: { offset: number; bytes: number }[] }
  | { kind: "array-all-references"; dataOffset: number }
  | { kind: "array-repeating"; firstReferenceOffset: number; series: { pointerCount: number; skipBytes: number }[] };

export class NativeAotGcDescriptors {
  constructor(readonly references: NativeAotFunctionReferences) {}

  async #word(address: number): Promise<bigint> {
    const image = this.references.image;
    if (!Number.isSafeInteger(address) || address < 0 || address % image.pointerSize ||
      !image.isMappedRange(address, image.pointerSize) || image.isExecutableAddress(address)) {
      throw new Error("GC descriptor has an invalid mapped range or alignment.");
    }
    const low = await this.references.data.unsigned(address, 4);
    const high = image.pointerSize === 8 ? await this.references.data.unsigned(address + 4, 4) : 0;
    if (low === null || high === null) throw new Error("GC descriptor contains an unreadable scalar.");
    return BigInt(low) + (BigInt(high) << 32n);
  }

  async #unsigned(address: number): Promise<number> {
    const value = Number(await this.#word(address));
    if (!Number.isSafeInteger(value)) throw new Error("GC descriptor scalar exceeds safe integer precision.");
    return value;
  }

  async #signed(address: number): Promise<number> {
    const value = Number(BigInt.asIntN(this.references.image.pointerSize * 8, await this.#word(address)));
    if (!Number.isSafeInteger(value)) throw new Error("GC descriptor signed scalar exceeds safe integer precision.");
    return value;
  }

  #range(rva: number, count: number): void {
    const size = (count > 0 ? count * 2 + 1 : -count + 2) * this.references.image.pointerSize;
    if (!count || !Number.isSafeInteger(size) || size > rva ||
      !this.references.image.isMappedRange(rva - size, size)) {
      throw new Error("GC descriptor series count exceeds its mapped storage.");
    }
  }

  async #object(type: Pick<NativeAotRuntimeType, "rva" | "baseSize">,
    count: number): Promise<NativeAotGcDescriptor> {
    const width = this.references.image.pointerSize;
    const series: { offset: number; bytes: number }[] = [];
    let previousEnd = width;
    for (let index = 0; index < count; index++) {
      const offset = await this.#unsigned(type.rva - (index * 2 + 2) * width);
      const bytes = await this.#signed(type.rva - (index * 2 + 3) * width) + type.baseSize;
      if (offset < previousEnd || offset % width || bytes <= 0 || bytes % width ||
        offset + bytes > type.baseSize - width) throw new Error("GC descriptor object series is outside its instance layout.");
      series.push({ offset, bytes });
      previousEnd = offset + bytes;
    }
    return { kind: "object", series };
  }

  async #referenceArray(type: Pick<NativeAotRuntimeType, "rva" | "baseSize">,
    count: number): Promise<NativeAotGcDescriptor> {
    const width = this.references.image.pointerSize;
    const dataOffset = await this.#unsigned(type.rva - width * 2);
    const adjustment = await this.#signed(type.rva - width * 3);
    if (count !== 1 || dataOffset !== type.baseSize - width || adjustment !== -type.baseSize) {
      throw new Error("GC descriptor reference-array encoding does not match its data layout.");
    }
    return { kind: "array-all-references", dataOffset };
  }

  async #repeatingArray(type: Pick<NativeAotRuntimeType, "rva" | "baseSize">,
    count: number, componentSize: number): Promise<NativeAotGcDescriptor> {
    const width = this.references.image.pointerSize;
    const firstReferenceOffset = await this.#unsigned(type.rva - width * 2);
    const leadingBytes = firstReferenceOffset - type.baseSize + width;
    if (leadingBytes < 0 || leadingBytes >= componentSize || leadingBytes % width) {
      throw new Error("GC descriptor first array reference is outside its element layout.");
    }
    const series: { pointerCount: number; skipBytes: number }[] = [];
    const halfBits = BigInt(width * 4);
    let stride = 0;
    for (let index = 0; index < -count; index++) {
      const packed = await this.#word(type.rva - (index + 3) * width);
      const pointerCount = Number(packed & ((1n << halfBits) - 1n));
      const skipBytes = Number(packed >> halfBits);
      if (!pointerCount || skipBytes % width) throw new Error("GC descriptor has an invalid repeating series.");
      series.push({ pointerCount, skipBytes });
      stride += pointerCount * width + skipBytes;
    }
    if (stride !== componentSize || series.at(-1)!.skipBytes < leadingBytes) {
      throw new Error("GC descriptor repeating stride does not match the array component size.");
    }
    return { kind: "array-repeating", firstReferenceOffset, series };
  }

  async #decode(type: Pick<NativeAotRuntimeType, "rva" | "flags" | "baseSize">): Promise<NativeAotGcDescriptor> {
    const width = this.references.image.pointerSize;
    const count = await this.#signed(type.rva - width);
    this.#range(type.rva, count);
    const elementType = (type.flags >>> 26) & 31;
    if (![0x17, 0x18].includes(elementType)) {
      if (count < 0) throw new Error("GC descriptor repeating series requires an array type.");
      return this.#object(type, count);
    }
    const componentSize = type.flags & 0xffff;
    if (!(type.flags & 0x80000000) || !componentSize || componentSize % width) {
      throw new Error("GC descriptor array has an invalid component size.");
    }
    return count > 0 ? this.#referenceArray(type, count) : this.#repeatingArray(type, count, componentSize);
  }

  async read(type: Pick<NativeAotRuntimeType, "rva" | "flags" | "baseSize" | "numVtableSlots">):
    Promise<NativeAotGcDescriptor | null> {
    // GCDescEncoder is identical in .NET 9/10; HasPointersFlag requires a backwards-growing descriptor.
    // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Runtime/GCDescEncoder.cs
    // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/gc/gcdesc.h
    // Necessary MethodTables (zero slots) have no GCDesc, even when HasPointersFlag is set.
    // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/nativeaot/Runtime.Base/src/Internal/Runtime/Augments/RuntimeAugments.cs
    if (!(type.flags & 0x01000000) || !type.numVtableSlots) return null;
    try { return await this.#decode(type); }
    catch (error) {
      this.references.issues.add(error instanceof Error ? error.message : "GC descriptor decoding failed.");
      return null;
    }
  }
}
