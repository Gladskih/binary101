export interface PortablePdbDocument {
  name: string | null;
  language: string | null;
  hashAlgorithm: string | null;
  hashSize: number | null;
}

export interface PortablePdbCustomRecord {
  kind: string | null;
  size: number | null;
}

export type PortablePdbLocal =
  | { kind: "variable"; name: string | null; slot: number; attributes: number }
  | { kind: "constant"; name: string | null; signatureSize: number | null };

export interface PortablePdbInfo {
  id: { guid: string | null; stamp: number };
  entryPoint: number;
  tables: { name: string; declaredRows: number; parsedRows: number }[];
  documents: PortablePdbDocument[];
  locals: PortablePdbLocal[];
  methodsWithSequencePoints: number;
  sequencePoints: { visible: number; hidden: number };
  customRecords: PortablePdbCustomRecord[];
}
