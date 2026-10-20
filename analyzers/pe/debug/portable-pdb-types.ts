import type { PortablePdbImport } from "./portable-pdb-imports.js";
import type { PortablePdbCustomData } from "./portable-pdb-custom-types.js";
import type { PortablePdbConstant } from "./portable-pdb-constants.js";

export interface PortablePdbDocument {
  name: string | null;
  language: string | null;
  hashAlgorithm: string | null;
  hashSize: number | null;
}

export interface PortablePdbCustomRecord {
  kind: string | null;
  size: number | null;
  parent: { tableId: number; row: number };
  data?: PortablePdbCustomData;
}

export type PortablePdbLocal =
  | { kind: "variable"; name: string | null; slot: number; attributes: number }
  | { kind: "constant"; name: string | null; signatureSize: number | null; constant: PortablePdbConstant | null };

export interface PortablePdbInfo {
  id: { guid: string | null; stamp: number };
  entryPoint: number;
  tables: { name: string; declaredRows: number; parsedRows: number }[];
  documents: PortablePdbDocument[];
  locals: PortablePdbLocal[];
  imports: { parent: number; imports: PortablePdbImport[] }[];
  methodsWithSequencePoints: number;
  sequencePoints: { visible: number; hidden: number };
  customRecords: PortablePdbCustomRecord[];
}
