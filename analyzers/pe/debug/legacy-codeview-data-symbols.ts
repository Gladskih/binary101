import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";

export interface LegacyCodeViewDataSymbol {
  kind: "data" | "public" | "block" | "label";
  typeIndex?: number;
  location?: { segment: number; offset: number };
  publicFlags?: number;
  codeLength?: number;
  scopeOffsets?: { parent: number; end: number };
  flags?: number;
}

interface DataSymbolLayout {
  kind: LegacyCodeViewDataSymbol["kind"];
  nameOffset: number;
  nameEncoding: "ansi" | "utf8";
  narrowType?: boolean;
  typeIndexOffset?: number;
  publicFlagsOffset?: number;
  locationOffset?: number;
  segmentOffset?: number;
  codeLengthOffset?: number;
  parentOffset?: number;
  endOffset?: number;
  flagsOffset?: number;
}

// DATASYM32_16t, DATASYM32, PUBSYM32, LABELSYM32 and BLOCKSYM32 from pinned
// Microsoft cvinfo.h: https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h#L3619
// Block/label records: https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h#L3806
const DATA_SYMBOL_LAYOUTS = new Map<number, DataSymbolLayout>([
  [0x0201, { kind: "data", nameOffset: 12, nameEncoding: "ansi", narrowType: true,
    typeIndexOffset: 10, locationOffset: 4, segmentOffset: 8 }],
  [0x0202, { kind: "data", nameOffset: 12, nameEncoding: "ansi", narrowType: true,
    typeIndexOffset: 10, locationOffset: 4, segmentOffset: 8 }],
  [0x0203, { kind: "public", nameOffset: 12, nameEncoding: "ansi", narrowType: true,
    typeIndexOffset: 10, locationOffset: 4, segmentOffset: 8 }],
  [0x1007, { kind: "data", nameOffset: 14, nameEncoding: "ansi", typeIndexOffset: 4,
    locationOffset: 8, segmentOffset: 12 }],
  [0x1008, { kind: "data", nameOffset: 14, nameEncoding: "ansi", typeIndexOffset: 4,
    locationOffset: 8, segmentOffset: 12 }],
  [0x110c, { kind: "data", nameOffset: 14, nameEncoding: "utf8", typeIndexOffset: 4,
    locationOffset: 8, segmentOffset: 12 }],
  [0x110d, { kind: "data", nameOffset: 14, nameEncoding: "utf8", typeIndexOffset: 4,
    locationOffset: 8, segmentOffset: 12 }],
  [0x1009, { kind: "public", nameOffset: 14, nameEncoding: "ansi", publicFlagsOffset: 4,
    locationOffset: 8, segmentOffset: 12 }],
  [0x110e, { kind: "public", nameOffset: 14, nameEncoding: "utf8", publicFlagsOffset: 4,
    locationOffset: 8, segmentOffset: 12 }],
  [0x0207, { kind: "block", nameOffset: 22, nameEncoding: "ansi", parentOffset: 4,
    endOffset: 8, codeLengthOffset: 12, locationOffset: 16, segmentOffset: 20 }],
  [0x1103, { kind: "block", nameOffset: 22, nameEncoding: "utf8", parentOffset: 4,
    endOffset: 8, codeLengthOffset: 12, locationOffset: 16, segmentOffset: 20 }],
  [0x0209, { kind: "label", nameOffset: 11, nameEncoding: "ansi", locationOffset: 4,
    segmentOffset: 8, flagsOffset: 10 }],
  [0x1105, { kind: "label", nameOffset: 11, nameEncoding: "utf8", locationOffset: 4,
    segmentOffset: 8, flagsOffset: 10 }]
]);

const readName = async (reader: LegacyCodeViewReader, offset: number,
  encoding: DataSymbolLayout["nameEncoding"]): Promise<string> => encoding === "utf8"
  ? reader.utf8(offset) : (await reader.pascal(offset)).name;

const readFixedSymbol = (fields: DataView, layout: DataSymbolLayout): LegacyCodeViewDataSymbol => {
  const read16 = (offset: number): number => fields.getUint16(offset - 4, true);
  const read32 = (offset: number): number => fields.getUint32(offset - 4, true);
  return { kind: layout.kind,
    ...(layout.typeIndexOffset === undefined ? {} : { typeIndex: layout.narrowType
      ? read16(layout.typeIndexOffset) : read32(layout.typeIndexOffset) }),
    ...(layout.locationOffset === undefined || layout.segmentOffset === undefined ? {} : {
      location: { offset: read32(layout.locationOffset), segment: read16(layout.segmentOffset) } }),
    ...(layout.publicFlagsOffset === undefined ? {} : { publicFlags: read32(layout.publicFlagsOffset) }),
    ...(layout.codeLengthOffset === undefined ? {} : { codeLength: read32(layout.codeLengthOffset) }),
    ...(layout.parentOffset === undefined || layout.endOffset === undefined ? {} : {
      scopeOffsets: { parent: read32(layout.parentOffset), end: read32(layout.endOffset) } }),
    ...(layout.flagsOffset === undefined ? {} : { flags: fields.getUint8(layout.flagsOffset - 4) }) };
};

/** Read C7 symbol metadata and names from the same bounded record-local reader. */
export const readLegacyCodeViewDataSymbol = async (
  reader: LegacyCodeViewReader, type: number
): Promise<{ name?: string; data: LegacyCodeViewDataSymbol } | null> => {
  const layout = DATA_SYMBOL_LAYOUTS.get(type);
  if (!layout) return null;
  let data: LegacyCodeViewDataSymbol = { kind: layout.kind };
  try { data = readFixedSymbol(await reader.view(4, layout.nameOffset - 4), layout); }
  catch (error) {
    reader.warn(`CodeView symbol fixed fields: ${String(error)}`);
    return { data };
  }
  try { return { name: await readName(reader, layout.nameOffset, layout.nameEncoding), data }; }
  catch (error) {
    reader.warn(`CodeView symbol name: ${String(error)}`);
    return { data };
  }
};
