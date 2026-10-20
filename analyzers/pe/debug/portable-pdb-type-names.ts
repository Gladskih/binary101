import type { PeClrMetadataTables } from "../clr/types.js";
import type { PortablePdbTypeReference } from "./portable-pdb-constants.js";

export class PortablePdbTypeNames {
  private readonly names = new Map<string, string | null>();
  private readonly specifications = new Map<number, PortablePdbTypeReference>();
  constructor(metadata: PeClrMetadataTables | undefined) {
    metadata?.typeRefs.forEach(type => this.names.set(`1:${type.row}`, type.fullName));
    metadata?.typeDefs.forEach(type => this.names.set(`2:${type.row}`, type.fullName));
    metadata?.additionalTables?.find(table => table.tableId === 0x1b)?.rows.forEach((row, index) => {
      const signature = row["Signature"];
      if (!signature || typeof signature !== "object" || !("type" in signature)) return;
      const match = /^(?:class|valuetype) (TypeDef|TypeRef|TypeSpec)#(\d+)$/.exec(signature.type ?? "");
      if (match) this.specifications.set(index + 1, {
        tableId: ({ TypeDef: 2, TypeRef: 1, TypeSpec: 0x1b } as Record<string, number>)[match[1]!]!,
        row: Number(match[2])
      });
    });
  }
  get(reference: PortablePdbTypeReference | undefined): string | null {
    const visited = new Set<string>();
    let current = reference;
    let name: string | null = null;
    while (current) {
      const key = `${current.tableId}:${current.row}`;
      if (visited.has(key)) break;
      visited.add(key);
      if (this.names.has(key)) { name = this.names.get(key)!; break; }
      current = current.tableId === 0x1b ? this.specifications.get(current.row) : undefined;
    }
    visited.forEach(key => this.names.set(key, name));
    return name;
  }
}
