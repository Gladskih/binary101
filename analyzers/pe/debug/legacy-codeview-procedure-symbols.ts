import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";

export interface LegacyCodeViewProcedure {
  referenceKind: "typeIndex" | "procedureId";
  reference?: number;
  codeLength?: number;
  debugStart?: number;
  debugEnd?: number;
  storedLocation?: { segment: number; offset: number };
  scopeOffsets?: { parent: number; end: number; next: number };
  flags?: number;
}

interface ProcedureLayout {
  nameOffset: number;
  typeOffset: number;
  narrowType: boolean;
  nameEncoding: "ansi" | "utf8";
  referenceKind: LegacyCodeViewProcedure["referenceKind"];
}

interface ParsedProcedure extends LegacyCodeViewProcedure {
  codeLength: number;
  debugStart: number;
  debugEnd: number;
}

// PROCSYM32_16t and PROCSYM32 field positions and symbol IDs are from pinned
// Microsoft cvinfo.h: https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h#L2760
const PROCEDURE_LAYOUTS = new Map<number, ProcedureLayout>([
  [0x0204, { nameOffset: 37, typeOffset: 34, narrowType: true, nameEncoding: "ansi", referenceKind: "typeIndex" }],
  [0x0205, { nameOffset: 37, typeOffset: 34, narrowType: true, nameEncoding: "ansi", referenceKind: "typeIndex" }],
  [0x100a, { nameOffset: 39, typeOffset: 28, narrowType: false, nameEncoding: "ansi", referenceKind: "typeIndex" }],
  [0x100b, { nameOffset: 39, typeOffset: 28, narrowType: false, nameEncoding: "ansi", referenceKind: "typeIndex" }],
  [0x110f, { nameOffset: 39, typeOffset: 28, narrowType: false, nameEncoding: "utf8", referenceKind: "typeIndex" }],
  [0x1110, { nameOffset: 39, typeOffset: 28, narrowType: false, nameEncoding: "utf8", referenceKind: "typeIndex" }],
  [0x1146, { nameOffset: 39, typeOffset: 28, narrowType: false, nameEncoding: "utf8", referenceKind: "procedureId" }],
  [0x1147, { nameOffset: 39, typeOffset: 28, narrowType: false, nameEncoding: "utf8", referenceKind: "procedureId" }]
]);

const readName = async (reader: LegacyCodeViewReader, offset: number,
  encoding: ProcedureLayout["nameEncoding"]): Promise<string> => encoding === "utf8"
  ? reader.utf8(offset) : (await reader.pascal(offset)).name;

const readFixedFields = (fields: DataView, layout: ProcedureLayout): ParsedProcedure => {
  const read32 = (offset: number): number => fields.getUint32(offset - 4, true);
  const read16 = (offset: number): number => fields.getUint16(offset - 4, true);
  const typeReference = layout.narrowType ? read16(layout.typeOffset) : read32(layout.typeOffset);
  const codeLength = read32(16);
  const debugStart = read32(20);
  const debugEnd = read32(24);
  const offset = read32(layout.narrowType ? 28 : 32);
  const segment = read16(layout.narrowType ? 32 : 36);
  const flags = fields.getUint8((layout.narrowType ? 36 : 38) - 4);
  return { referenceKind: layout.referenceKind, reference: typeReference, codeLength, debugStart,
    debugEnd, storedLocation: { segment, offset }, scopeOffsets: { parent: read32(4),
      end: read32(8), next: read32(12) }, flags };
};

const validateDebugSpan = (reader: LegacyCodeViewReader, procedure: ParsedProcedure): void => {
  if (procedure.debugStart > procedure.debugEnd) reader.warn("CodeView procedure debug span starts after it ends.");
  if (procedure.debugStart > procedure.codeLength || procedure.debugEnd > procedure.codeLength) {
    reader.warn("CodeView procedure debug span exceeds the stored code length.");
  }
};

/** Preserve C7 procedure fields and names without resolving section or scope references. */
export const readLegacyCodeViewProcedureSymbol = async (
  reader: LegacyCodeViewReader, type: number
): Promise<{ name?: string; procedure: LegacyCodeViewProcedure } | null> => {
  const layout = PROCEDURE_LAYOUTS.get(type);
  if (!layout) return null;
  let procedure: ParsedProcedure;
  try {
    procedure = readFixedFields(await reader.view(4, layout.nameOffset - 4), layout);
  } catch (error) {
    reader.warn(`CodeView procedure fixed fields: ${String(error)}`);
    return { procedure: { referenceKind: layout.referenceKind } };
  }
  validateDebugSpan(reader, procedure);
  try { return { name: await readName(reader, layout.nameOffset, layout.nameEncoding), procedure }; }
  catch (error) {
    reader.warn(`CodeView procedure name: ${String(error)}`);
    return { procedure };
  }
};
