import type { FileRangeReader } from "../../file-range-reader.js";
import { readMappedRvaPrefix } from "../rva-byte-reader.js";
import { isRvaRange } from "../rva-mapping.js";
import type { RvaToOffset } from "../types.js";
import type { PeClrReadyToRun, PeClrReadyToRunCoreHeader } from "./ready-to-run-types.js";
import { readReadyToRunDirectory } from "./ready-to-run-directory.js";
import { decodeReadyToRunSections, type ReadyToRunSectionCache } from "./ready-to-run-sections.js";
import { readyToRunPointerSize } from "./ready-to-run-target.js";
import { validateReadyToRunReferences } from "./ready-to-run-references.js";

class ComponentHeaders {
  readonly #cache = new Map<number, { size: number; parsed: Promise<PeClrReadyToRunCoreHeader | undefined> }>();
  constructor(readonly reader: FileRangeReader, readonly mapper: RvaToOffset,
    readonly data: PeClrReadyToRun, readonly machine: number | undefined,
    readonly sections: ReadyToRunSectionCache) {}

  read(rva: number, size: number, scope: string): Promise<PeClrReadyToRunCoreHeader | undefined> {
    const cached = this.#cache.get(rva);
    if (cached) {
      if (cached.size === size) return cached.parsed;
      this.data.issues.push(`${scope}: shared core header has conflicting sizes.`);
      return Promise.resolve(undefined);
    }
    const parsed = this.#parse(rva, size, scope);
    this.#cache.set(rva, { size, parsed });
    return parsed;
  }

  async #parse(rva: number, size: number, scope: string): Promise<PeClrReadyToRunCoreHeader | undefined> {
    const issues: string[] = [];
    try {
      if (!isRvaRange(rva, size)) throw new Error("invalid core header RVA range");
      // READYTORUN_CORE_HEADER has flags/count only, unlike the image-wide 16-byte header.
      // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/inc/readytorun.h
      const view = await readMappedRvaPrefix(this.reader, rva, Math.min(size, 8), this.mapper);
      if (view.byteLength < 8) throw new Error("core header is truncated");
      const sectionCount = view.getUint32(4, true);
      const sections = await readReadyToRunDirectory(this.reader, this.mapper, rva + 8,
        size - 8, sectionCount, issues);
      await decodeReadyToRunSections(this.reader, this.mapper, sections.filter(section => section.type !== 115),
        readyToRunPointerSize(this.machine), issues, this.sections);
      if (sections.some(section => section.type === 115)) {
        issues.push("ComponentAssemblies is image-wide and cannot nest in a component core header.");
      }
      validateReadyToRunReferences([
        ...this.data.sections.filter(section => section.type === 102), ...sections
      ], this.machine, issues);
      return { flags: view.getUint32(0, true), sectionCount, sections };
    } catch (error) {
      issues.push(error instanceof Error ? error.message : "component core header decoding failed");
      return undefined;
    } finally { this.data.issues.push(...issues.map(message => `${scope}: ${message}`)); }
  }
}

export const decodeReadyToRunComponents = async (
  reader: FileRangeReader, mapper: RvaToOffset, data: PeClrReadyToRun, machine: number | undefined,
  cache: ReadyToRunSectionCache = new Map()
): Promise<void> => {
  const tables = data.sections.filter(section => section.type === 115);
  if (!tables.length) return;
  if (tables.length !== 1) { data.issues.push("ComponentAssemblies section is ambiguous."); return; }
  const table = tables[0]!.decoded;
  if (table?.kind !== "components") return;
  const headers = new ComponentHeaders(reader, mapper, data, machine, cache);
  for (const [index, entry] of table.entries.entries()) {
    const coreHeader = await headers.read(entry.coreHeaderRva, entry.coreHeaderSize,
      `ReadyToRun component ${index + 1}`);
    if (coreHeader) entry.coreHeader = coreHeader;
  }
};
