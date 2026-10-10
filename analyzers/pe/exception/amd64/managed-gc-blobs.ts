import type { FileRangeReader } from "../../../file-range-reader.js";
import { readMappedRvaPrefix } from "../../rva-byte-reader.js";
import { mappedRvaSpan } from "../../rva-mapping.js";
import type { RvaToOffset } from "../../types.js";
import { parseX64GcInfo } from "../../../native-aot/gc-info-x64.js";
import type { ManagedGcInfo } from "../../../native-aot/gc-info-types.js";

/** Per-image GC blob cache; next unwind records and mapped storage bound every read. */
export class PeManagedGcBlobs {
  readonly #ends: Map<number, number | undefined>;
  readonly #cache = new Map<number, Promise<ManagedGcInfo | null>>();
  constructor(readonly reader: FileRangeReader, readonly mapper: RvaToOffset,
    unwindRvas: Set<number>, readonly version: 3 | 4, readonly warnings: Set<string>) {
    const sorted = [...unwindRvas].sort((left, right) => left - right);
    this.#ends = new Map(sorted.map((rva, index) => [rva, sorted[index + 1]]));
  }

  read(unwindRva: number, gcRva: number): Promise<ManagedGcInfo | null> {
    const cached = this.#cache.get(gcRva);
    if (cached) return cached;
    const result = this.#read(unwindRva, gcRva);
    this.#cache.set(gcRva, result);
    return result;
  }

  async #read(unwindRva: number, gcRva: number): Promise<ManagedGcInfo | null> {
    const span = mappedRvaSpan(this.mapper, gcRva, this.reader.size, this.reader.size);
    const end = this.#ends.get(unwindRva);
    if (!span || (end !== undefined && end <= gcRva)) {
      this.warnings.add("Managed GC info overlaps another unwind record or is unmapped.");
      return null;
    }
    const view = await readMappedRvaPrefix(this.reader, gcRva,
      Math.min(span.size, end === undefined ? span.size : end - gcRva), this.mapper);
    const warnings = new Set<string>();
    const info = parseX64GcInfo(new Uint8Array(view.buffer, view.byteOffset, view.byteLength), this.version, warnings);
    warnings.forEach(warning => this.warnings.add(`Managed GC info: ${warning}`));
    return info;
  }
}
