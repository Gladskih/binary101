import type { ClrHeapReaders } from "../clr/metadata-heaps.js";
import { decodeMetadataUtf8 } from "../clr/metadata-utf8.js";
import { PortablePdbBlobReader } from "./portable-pdb-blob.js";

export interface PortablePdbImport {
  kind: number;
  alias?: string | null;
  targetNamespace?: string | null;
  targetAssembly?: number;
  targetType?: { tableId: number; row: number };
}

// Imports Blob terminal order and TypeDefOrRefOrSpecEncoded (ECMA-335 II.23.2.8).
// https://github.com/dotnet/runtime/blob/main/docs/design/specs/PortablePdb-Metadata.md#imports-blob
const IMPORT_FIELDS: Readonly<Record<number, readonly (keyof PortablePdbImport)[]>> = {
  1: ["targetNamespace"], 2: ["targetAssembly", "targetNamespace"], 3: ["targetType"],
  4: ["alias", "targetNamespace"], 5: ["alias"], 6: ["alias", "targetAssembly"],
  7: ["alias", "targetNamespace"], 8: ["alias", "targetAssembly", "targetNamespace"],
  9: ["alias", "targetType"]
};

export class PortablePdbImportReader {
  private readonly decoded = new Map<number, PortablePdbImport[]>();
  private readonly decodeText = (bytes: Uint8Array | null, context: string): string | null =>
    bytes ? decodeMetadataUtf8(bytes, this.heaps.issues, context) : null;
  constructor(private readonly heaps: ClrHeapReaders,
    private readonly referencedRows: ReadonlyMap<number, number>) {}
  private text(index: number): string | null {
    return this.heaps.decodeBlob(index, "Portable PDB import text", this.decodeText);
  }
  private validateReference(table: number, row: number, name: string): void {
    if (!row || row > (this.referencedRows.get(table) ?? 0)) {
      this.heaps.issues.push(`Portable PDB import ${name} index is out of range.`);
    }
  }
  private assembly(cursor: PortablePdbBlobReader): number {
    const row = cursor.compressed();
    this.validateReference(0x23, row, "AssemblyRef");
    return row;
  }
  private type(cursor: PortablePdbBlobReader): NonNullable<PortablePdbImport["targetType"]> {
    const encoded = cursor.compressed();
    const tableId = [0x02, 0x01, 0x1b][encoded & 3] ?? -1;
    const row = encoded >>> 2;
    this.validateReference(tableId, row, "type");
    return { tableId, row };
  }
  private record(cursor: PortablePdbBlobReader): PortablePdbImport {
    const kind = cursor.compressed();
    const fields = IMPORT_FIELDS[kind];
    if (!fields) throw new Error(`unsupported import kind ${kind}`);
    const result: PortablePdbImport = { kind };
    for (const field of fields) {
      switch (field) {
        case "alias": result.alias = this.text(cursor.compressed()); break;
        case "targetNamespace": result.targetNamespace = this.text(cursor.compressed()); break;
        case "targetAssembly": result.targetAssembly = this.assembly(cursor); break;
        case "targetType": result.targetType = this.type(cursor); break;
      }
    }
    return result;
  }
  read(index: number): PortablePdbImport[] {
    const cached = this.decoded.get(index);
    if (cached) return cached;
    const result: PortablePdbImport[] = [];
    const bytes = this.heaps.getBlob(index, "ImportScope.Imports");
    if (bytes) {
      const cursor = new PortablePdbBlobReader(bytes);
      try {
        while (cursor.remaining) result.push(this.record(cursor));
      } catch (error) {
        this.heaps.issues.push(`Portable PDB imports: ${(error as Error).message}.`);
      }
    }
    this.decoded.set(index, result);
    return result;
  }
}
