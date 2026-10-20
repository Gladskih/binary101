import type { ClrHeapReaders } from "../clr/metadata-heaps.js";
import { PORTABLE_PDB_CUSTOM_KINDS } from "./portable-pdb-custom-kinds.js";
import { decodeCustomText } from "./portable-pdb-custom-text.js";
import { decodeCustomState } from "./portable-pdb-custom-state.js";
import { analyzePortablePdbSource } from "./portable-pdb-source.js";
import type { PortablePdbCustomData } from "./portable-pdb-custom-types.js";

export class PortablePdbCustomReader {
  private readonly decoded = new Map<string, Promise<PortablePdbCustomData | undefined>>();
  constructor(private readonly heaps: ClrHeapReaders,
    private readonly counts: ReadonlyMap<number, number>) {}
  private async decode(kind: string, index: number): Promise<PortablePdbCustomData | undefined> {
    const descriptor = PORTABLE_PDB_CUSTOM_KINDS[kind]!;
    const bytes = this.heaps.getBlob(index, `Portable PDB ${descriptor.name}`);
    if (!bytes) return undefined;
    try {
      if (descriptor.family === "text") return decodeCustomText(descriptor.type, bytes);
      if (descriptor.family === "state") return decodeCustomState(descriptor.type, bytes, this.counts);
      return { type: "embeddedSource", source: await analyzePortablePdbSource(bytes, this.heaps.issues) };
    } catch (error) {
      this.heaps.issues.push(`Portable PDB ${descriptor.name}: ${(error as Error).message}.`);
      return undefined;
    }
  }
  async read(kind: string | null, index: number, parentTable: number): Promise<PortablePdbCustomData | undefined> {
    if (!kind || !Object.hasOwn(PORTABLE_PDB_CUSTOM_KINDS, kind)) return undefined;
    const descriptor = PORTABLE_PDB_CUSTOM_KINDS[kind]!;
    if (!descriptor.parents.includes(parentTable)) {
      this.heaps.issues.push(`Portable PDB ${descriptor.name} has an unexpected parent table.`);
    }
    const key = `${kind}:${index}`;
    let result = this.decoded.get(key);
    if (!result) {
      result = this.decode(kind, index);
      this.decoded.set(key, result);
    }
    return result;
  }
}
