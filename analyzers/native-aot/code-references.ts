import type { NativeAotMetadataSection } from "./format.js";
import type { NativeAotVirtualImage } from "./virtual-image-types.js";
import type { NativeAotFunctionPointers } from "./function-pointers.js";

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
  readonly #name: string;
  readonly #cache = new Map<number, Promise<number | null>>();

  constructor(image: NativeAotVirtualImage, sections: NativeAotMetadataSection[], issues: Set<string>,
    sectionType: 308 | 331 | 333 = 308, readonly pointers?: NativeAotFunctionPointers) {
    this.#image = image;
    this.#issues = issues;
    // NativeLayout methods use NativeReferences (331); reflection maps use CommonFixups (308).
    // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Runtime/MetadataBlob.cs
    this.#name = new Map([[308, "Common fixups"], [331, "Native references"],
      [333, "Native statics"]]).get(sectionType)!;
    const tables = sections.filter(section => section.type === sectionType);
    this.#table = tables.length === 1 ? tables[0] : undefined;
    if (!this.#table) issues.add(`${this.#name} table is missing or ambiguous.`);
    else if (this.#table.size !== null && this.#table.size % 4) {
      issues.add(`${this.#name} table ends with an incomplete pointer.`);
    }
  }

  validateDataIndex(index: number): void {
    if (this.#table && !isReferenceIndex(index, this.#table.size)) {
      this.#issues.add(`${this.#name} data index is outside the table.`);
    }
  }

  resolveData(index: number): Promise<number | null> {
    if (!this.#table) return Promise.resolve(null);
    if (!isReferenceIndex(index, this.#table.size)) {
      this.validateDataIndex(index);
      return Promise.resolve(null);
    }
    return this.#target(index);
  }

  async resolve(index: number): Promise<number | null> {
    const target = await this.#target(index);
    if (target === null) return null;
    if (this.pointers) return this.pointers.resolve(target);
    if (!Number.isSafeInteger(target) || !this.#image.isExecutableAddress(target)) {
      this.#issues.add(`${this.#name} code target is not file-backed executable code.`);
      return null;
    }
    return target;
  }

  #target(index: number): Promise<number | null> {
    const cached = this.#cache.get(index);
    if (cached) return cached;
    const result = this.#read(index);
    this.#cache.set(index, result);
    return result;
  }

  async #read(index: number): Promise<number | null> {
    const table = this.#table;
    if (!table) return null;
    try {
      if (!isReferenceIndex(index, table.size)) {
        throw new Error(`${this.#name} code index is outside the table.`);
      }
      const slot = table.rva + index * 4;
      const view = await this.#image.readData(slot, 4, 4);
      if (!view || view.byteLength !== 4) throw new Error(`${this.#name} code pointer is truncated or unreadable.`);
      return slot + view.getInt32(0, true);
    } catch (error) {
      this.#issues.add(error instanceof Error ? error.message : `${this.#name} read failed.`);
      return null;
    }
  }
}
