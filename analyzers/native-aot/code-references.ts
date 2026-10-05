import type { NativeAotMetadataSection } from "./format.js";
import type { NativeAotVirtualImage } from "./virtual-image-types.js";

const isReferenceIndex = (index: number, size: number | null): boolean =>
  size !== null && Number.isSafeInteger(size) &&
  Number.isSafeInteger(index) && index >= 0 && index < Math.floor(size / 4);

// CommonFixupsTable holds signed slot-relative int32 pointers on non-Wasm NativeAOT targets.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/nativeaot/Common/src/Internal/Runtime/TypeLoader/ExternalReferencesTable.cs
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/TypeSystem/Common/TargetDetails.cs
export class NativeAotCodeReferences {
  readonly #image: NativeAotVirtualImage;
  readonly #issues: Set<string>;
  readonly #table: NativeAotMetadataSection | undefined;
  readonly #cache = new Map<number, number | null>();

  constructor(image: NativeAotVirtualImage, sections: NativeAotMetadataSection[], issues: Set<string>) {
    this.#image = image;
    this.#issues = issues;
    const tables = sections.filter(section => section.type === 308);
    this.#table = tables.length === 1 ? tables[0] : undefined;
    if (!this.#table) issues.add("Common fixups table is missing or ambiguous.");
    else if (this.#table.size !== null && this.#table.size % 4) {
      issues.add("Common fixups table ends with an incomplete pointer.");
    }
  }

  async resolve(index: number): Promise<number | null> {
    if (this.#cache.has(index)) return this.#cache.get(index)!;
    const value = await this.#read(index);
    this.#cache.set(index, value);
    return value;
  }

  async #read(index: number): Promise<number | null> {
    const table = this.#table;
    if (!table) return null;
    try {
      if (!isReferenceIndex(index, table.size)) {
        throw new Error("Common fixups code index is outside the table.");
      }
      const slot = table.rva + index * 4;
      const view = await this.#image.readData(slot, 4, 4);
      if (!view || view.byteLength !== 4) throw new Error("Common fixups code pointer is truncated or unreadable.");
      const target = slot + view.getInt32(0, true);
      if (!Number.isSafeInteger(target) || !this.#image.isExecutableAddress(target)) {
        throw new Error("Common fixups code target is not file-backed executable code.");
      }
      return target;
    } catch (error) {
      this.#issues.add(error instanceof Error ? error.message : "Common fixups read failed.");
      return null;
    }
  }
}
