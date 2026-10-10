import type { FileRangeReader } from "../file-range-reader.js";
import { parseX64GcInfo } from "../native-aot/gc-info-x64.js";
import type { ManagedGcInfo } from "../native-aot/gc-info-types.js";
import type { ElfProgramHeader } from "./types.js";
import { elfVirtualRange } from "./relocation-reader.js";

/** ELF NativeAOT LSDA tail, as consumed by UnixNativeCodeManager::EnumGcRefs.
 * https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/nativeaot/Runtime/unix/UnixNativeCodeManager.cpp
 */
export class ElfNativeAotGcBlobs {
  readonly #cache = new Map<bigint, Promise<ManagedGcInfo | null>>();
  readonly #ends: Map<bigint, bigint | undefined>;
  constructor(readonly reader: FileRangeReader, readonly headers: ElfProgramHeader[],
    addresses: Set<bigint>, readonly version: 3 | 4, readonly warnings: Set<string>) {
    const sorted = [...addresses].sort((left, right) => left < right ? -1 : 1);
    this.#ends = new Map(sorted.map((address, index) => [address, sorted[index + 1]]));
  }

  read(address: bigint): Promise<ManagedGcInfo | null> {
    const cached = this.#cache.get(address);
    if (cached) return cached;
    const result = this.#read(address);
    this.#cache.set(address, result);
    return result;
  }

  #range(address: bigint): { offset: number; size: number } {
    const segment = this.headers.find(header => header.type === 1 &&
      address >= header.vaddr && address < header.vaddr + header.filesz);
    if (!segment) throw new Error("NativeAOT LSDA is outside file-backed storage.");
    const next = this.#ends.get(address);
    const end = next !== undefined && next < segment.vaddr + segment.filesz
      ? next : segment.vaddr + segment.filesz;
    const range = elfVirtualRange(this.headers, address, end - address, this.reader.size);
    if (!range) throw new Error("NativeAOT LSDA file-backed storage is truncated.");
    return range;
  }

  async #read(address: bigint): Promise<ManagedGcInfo | null> {
    const range = this.#range(address);
    const view = await this.reader.read(range.offset, range.size);
    if (!view.byteLength) throw new Error("NativeAOT LSDA flags are truncated.");
    const flags = view.getUint8(0);
    if ((flags & 0xe0) || (flags & 3) === 3) throw new Error("NativeAOT LSDA flags are reserved.");
    if (flags & 3) return null;
    const skip = 1 + Number(!!(flags & 0x10)) * 4 + Number(!!(flags & 4)) * 4;
    if (skip >= view.byteLength) throw new Error("NativeAOT LSDA GC payload is truncated.");
    const warnings = new Set<string>();
    const info = parseX64GcInfo(new Uint8Array(view.buffer, view.byteOffset + skip,
      view.byteLength - skip), this.version, warnings);
    warnings.forEach(warning => this.warnings.add(`NativeAOT GC info: ${warning}`));
    return info;
  }
}
