import type { NativeAotFunctionReferences } from "./function-references.js";
import type { NativeFormatCursor } from "./native-format-cursor.js";

export type NativeAotVirtualSlot = { kind: "method" | "data"; rva: number } | { kind: "null" };
export interface NativeAotRuntimeType {
  rva: number;
  flags: number;
  baseSize: number;
  numVtableSlots: number;
  numInterfaces: number;
  hashCode: number;
  slots: NativeAotVirtualSlot[];
}
export interface NativeAotTypeMapEntry {
  typeIndex: number;
  metadataHandle: number;
  runtimeType: NativeAotRuntimeType | null;
}

export class NativeAotRuntimeTypes {
  readonly #cache = new Map<number, Promise<NativeAotRuntimeType | null>>();
  constructor(readonly references: NativeAotFunctionReferences) {}
  async read(cursor: NativeFormatCursor): Promise<NativeAotTypeMapEntry> {
    // TypeMetadataMapNode writes (CommonFixups type index, NativeMetadata handle).
    // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.Compiler/Compiler/DependencyAnalysis/TypeMetadataMapNode.cs
    const typeIndex = cursor.unsigned();
    const metadataHandle = cursor.unsigned();
    const rva = await this.references.common.resolveData(typeIndex);
    if (rva === null) return { typeIndex, metadataHandle, runtimeType: null };
    let parsed = this.#cache.get(rva);
    if (!parsed) { parsed = this.#readType(rva); this.#cache.set(rva, parsed); }
    return { typeIndex, metadataHandle, runtimeType: await parsed };
  }

  async #scalar(rva: number, size: 2 | 4): Promise<number> {
    const value = await this.references.data.unsigned(rva, size);
    if (value === null) throw new Error("MethodTable fixed header is unreadable.");
    return value;
  }

  async #readType(rva: number): Promise<NativeAotRuntimeType | null> {
    const image = this.references.image;
    try {
      // Sequential MethodTable header is 16 bytes + related-type pointer, then the vtable.
      // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/nativeaot/Common/src/Internal/Runtime/MethodTable.cs
      if (rva % image.pointerSize || image.isExecutableAddress(rva) ||
        !image.isMappedRange(rva, 16 + image.pointerSize)) {
        throw new Error("MethodTable header has an invalid mapped range or alignment.");
      }
      const flags = await this.#scalar(rva, 4);
      const baseSize = await this.#scalar(rva + 4, 4);
      const numVtableSlots = await this.#scalar(rva + 8 + image.pointerSize, 2);
      const numInterfaces = await this.#scalar(rva + 10 + image.pointerSize, 2);
      const hashCode = await this.#scalar(rva + 12 + image.pointerSize, 4);
      return { rva, flags, baseSize, numVtableSlots, numInterfaces, hashCode,
        slots: await this.#slots(rva + 16 + image.pointerSize, numVtableSlots) };
    } catch (error) {
      this.references.issues.add(error instanceof Error ? error.message : "MethodTable decoding failed.");
      return null;
    }
  }

  async #slots(rva: number, count: number): Promise<NativeAotVirtualSlot[]> {
    const slots: NativeAotVirtualSlot[] = [];
    const image = this.references.image;
    for (let index = 0; index < count; index++) {
      const address = rva + index * image.pointerSize;
      if (!image.isMappedRange(address, image.pointerSize)) {
        this.references.issues.add("MethodTable vtable is truncated.");
        break;
      }
      // EETypeNode.OutputVirtualSlots also emits generic dictionary pointers and empty slots.
      // Only targets inside file-backed executable ranges can supply instruction seeds.
      const target = await this.references.data.pointer(address);
      slots.push(target === null ? { kind: "null" } : {
        kind: image.isExecutableAddress(target) ? "method" : "data", rva: target });
    }
    return slots;
  }
}
