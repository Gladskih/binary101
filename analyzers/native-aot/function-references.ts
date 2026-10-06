import type { NativeAotMetadataSection } from "./format.js";
import type { NativeAotVirtualImage } from "./virtual-image-types.js";
import { NativeAotCodeReferences } from "./code-references.js";
import { NativeAotDehydratedData } from "./dehydrated-data.js";
import { NativeAotFunctionPointers } from "./function-pointers.js";

/** Lazy, shared reference tables for the function maps of one image. */
export class NativeAotFunctionReferences {
  readonly #tables = new Map<308 | 331 | 333, NativeAotCodeReferences>();
  readonly data: NativeAotDehydratedData;
  readonly pointers: NativeAotFunctionPointers;
  constructor(readonly image: NativeAotVirtualImage, readonly sections: NativeAotMetadataSection[],
    readonly issues: Set<string>) {
    this.data = new NativeAotDehydratedData(image, sections, issues);
    this.pointers = new NativeAotFunctionPointers(this.data, issues);
  }
  get common(): NativeAotCodeReferences { return this.#table(308); }
  get native(): NativeAotCodeReferences { return this.#table(331); }
  get statics(): NativeAotCodeReferences { return this.#table(333); }
  #table(type: 308 | 331 | 333): NativeAotCodeReferences {
    const cached = this.#tables.get(type);
    if (cached) return cached;
    const table = new NativeAotCodeReferences(this.image, this.sections, this.issues, type, this.pointers);
    this.#tables.set(type, table);
    return table;
  }
}
