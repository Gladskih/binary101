import type { NativeAotMetadataSection } from "./format.js";
import type { NativeAotVirtualImage } from "./virtual-image-types.js";
import type { NativeAotHydratedRun } from "./dehydrated-stream-types.js";
import { readNativeAotSectionBytes } from "./section-bytes.js";
import { readNativeAotDehydratedRuns } from "./dehydrated-stream.js";
import { findNativeAotHydratedRun, readNativeAotHydratedUnsigned } from "./hydrated-scalars.js";
import { readNativeAotHydratedRelative } from "./hydrated-relative.js";

/** Restores typed fields without materializing the whole hydrated image. */
export class NativeAotDehydratedData {
  readonly #cache = new Map<number, Promise<number | null>>();
  readonly #relativeCache = new Map<number, Promise<number | null>>();
  #loaded: Promise<NativeAotHydratedRun[]> | undefined;
  constructor(readonly image: NativeAotVirtualImage, readonly sections: NativeAotMetadataSection[],
    readonly issues: Set<string>) {}

  pointer(address: number): Promise<number | null> {
    const cached = this.#cache.get(address);
    if (cached) return cached;
    const result = this.#read(address);
    this.#cache.set(address, result);
    return result;
  }

  async unsigned(address: number, size: 2 | 4): Promise<number | null> {
    try {
      this.#loaded ??= this.#load();
      return await readNativeAotHydratedUnsigned(this.image, await this.#loaded, address, size);
    } catch (error) {
      this.issues.add(error instanceof Error ? error.message : "NativeAOT scalar read failed.");
      return null;
    }
  }

  relative(address: number): Promise<number | null> {
    let result = this.#relativeCache.get(address);
    if (!result) { result = this.#relative(address); this.#relativeCache.set(address, result); }
    return result;
  }

  async #relative(address: number): Promise<number | null> {
    try {
      this.#loaded ??= this.#load();
      return await readNativeAotHydratedRelative(this.image, await this.#loaded, address);
    } catch (error) {
      this.issues.add(error instanceof Error ? error.message : "NativeAOT relative pointer read failed.");
      return null;
    }
  }

  async #load(): Promise<NativeAotHydratedRun[]> {
    const streams = this.sections.filter(section => section.type === 207);
    if (!streams.length) return [];
    if (streams.length !== 1) { this.issues.add("DehydratedData section is ambiguous."); return []; }
    return readNativeAotDehydratedRuns(this.image, streams[0]!,
      await readNativeAotSectionBytes(this.image, streams[0]!, this.issues), this.issues);
  }

  async #storedPointer(address: number): Promise<number | null> {
    if (!this.image.isDataRange(address, this.image.pointerSize, this.image.pointerSize)) {
      throw new Error("NativeAOT absolute pointer is not readable in the image or DehydratedData.");
    }
    const value = await this.image.readPointerValue(address);
    if (value === 0n) return null;
    const target = await this.image.readPointerTarget(address);
    if (target === null) throw new Error("NativeAOT absolute pointer is unreadable or unresolved.");
    return target;
  }

  async #target(address: number): Promise<number | null> {
    this.#loaded ??= this.#load();
    const run = findNativeAotHydratedRun(await this.#loaded, address);
    if (!run) return this.#storedPointer(address);
    if (run.kind === "relative") {
      throw new Error("NativeAOT absolute pointer field is not an absolute pointer in DehydratedData.");
    }
    if (address + this.image.pointerSize > run.rva + run.size) {
      throw new Error("NativeAOT absolute pointer field crosses a dehydrated run boundary.");
    }
    if (run.kind === "zero") return null;
    if (run.kind === "copy") return this.#copiedPointer(run.sourceRva + address - run.rva);
    return run.target;
  }

  async #copiedPointer(address: number): Promise<number | null> {
    const view = await this.image.readData(address, this.image.pointerSize, 1);
    if (!view || view.byteLength !== this.image.pointerSize) {
      throw new Error("NativeAOT copied pointer is truncated or unreadable.");
    }
    const value = this.image.pointerSize === 8 ? view.getBigUint64(0, true) : BigInt(view.getUint32(0, true));
    if (value === 0n) return null;
    const target = this.image.toImageAddress?.(value) ?? await this.image.readPointerTarget(address);
    if (target === null) throw new Error("NativeAOT copied pointer could not be resolved.");
    return target;
  }

  async #read(address: number): Promise<number | null> {
    try {
      return await this.#target(address);
    } catch (error) {
      this.issues.add(error instanceof Error ? error.message : "NativeAOT absolute pointer read failed.");
      return null;
    }
  }
}
