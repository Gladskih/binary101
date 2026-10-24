import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";
import type { LegacyCodeViewTypeRecord } from "./legacy-codeview-type-records.js";
import { readLegacyCodeViewNumeric } from "./legacy-codeview-numeric.js";

export interface CodeViewAggregate {
  kind: "aggregate";
  memberCount?: number | string;
  properties: number;
  fieldList: number;
  derivedTypes?: number;
  vtableShape?: number;
  underlyingType?: number;
  size?: string;
}
export type CodeViewCompositeShape = CodeViewAggregate
  | { kind: "array"; elementType: number; indexType: number; stride?: number; size?: string }
  | { kind: "vector"; elementType: number; count: number; size?: string }
  | { kind: "matrix"; elementType: number; rows: number; columns: number;
      majorStride: number; attributes: number; size?: string };

interface AggregateLayout {
  prefix: number;
  properties: number;
  fieldList: number;
  derivedTypes?: number;
  vtableShape?: number;
  underlyingType?: number;
  memberCountOffset?: number;
  propertiesWidth?: 4;
}

// Packed lfClass/Structure/Interface, lfUnion, lfEnum and their 16t/ST/SZ variants.
// Offsets include the record length; sizes are CodeView numeric leaves.
// https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h
const NARROW_CLASS: AggregateLayout = { prefix: 14, properties: 8, fieldList: 6, derivedTypes: 10, vtableShape: 12 };
const WIDE_CLASS: AggregateLayout = { prefix: 20, properties: 6, fieldList: 8, derivedTypes: 12, vtableShape: 16 };
// LLVM's published *2 layouts: 32-bit properties, encoded uint64 member count.
// https://github.com/llvm/llvm-project/blob/007ca8ec1bd348000e42ada637c421cf5d28c11a/llvm/lib/DebugInfo/CodeView/TypeRecordMapping.cpp
const EXTENDED_CLASS: AggregateLayout = { ...WIDE_CLASS, properties: 4,
  propertiesWidth: 4, memberCountOffset: 20 };
const AGGREGATES = new Map<number, AggregateLayout>([
  [4, NARROW_CLASS], [5, NARROW_CLASS],
  [0x1004, WIDE_CLASS], [0x1005, WIDE_CLASS], [0x1504, WIDE_CLASS], [0x1505, WIDE_CLASS], [0x1519, WIDE_CLASS],
  [6, { prefix: 10, properties: 8, fieldList: 6 }],
  [0x1006, { prefix: 12, properties: 6, fieldList: 8 }], [0x1506, { prefix: 12, properties: 6, fieldList: 8 }],
  [7, { prefix: 12, properties: 10, fieldList: 8, underlyingType: 6 }],
  [0x1007, { prefix: 16, properties: 6, fieldList: 12, underlyingType: 8 }],
  [0x1507, { prefix: 16, properties: 6, fieldList: 12, underlyingType: 8 }],
  [0x1608, EXTENDED_CLASS], [0x1609, EXTENDED_CLASS], [0x160b, EXTENDED_CLASS],
  [0x160a, { prefix: 12, properties: 4, fieldList: 8, propertiesWidth: 4, memberCountOffset: 12 }]
]);
const ARRAY_PREFIXES = new Map([[3, 8], [0x1003, 12], [0x1503, 12],
  [0x1516, 16], [0x151b, 12], [0x151c, 21]]);

const aggregateHeader = (view: DataView, type: number, layout: AggregateLayout): CodeViewAggregate => {
  const index = (offset: number) => type < 0x1000 ? view.getUint16(offset, true) : view.getUint32(offset, true);
  const shape: CodeViewAggregate = { kind: "aggregate",
    properties: layout.propertiesWidth === 4
      ? view.getUint32(layout.properties, true) : view.getUint16(layout.properties, true),
    fieldList: index(layout.fieldList) };
  if (layout.memberCountOffset === undefined) shape.memberCount = view.getUint16(4, true);
  for (const key of ["derivedTypes", "vtableShape", "underlyingType"] as const) {
    const offset = layout[key];
    if (offset !== undefined) shape[key] = index(offset);
  }
  return shape;
};

const readAggregate = async (reader: LegacyCodeViewReader, type: number, layout: AggregateLayout) => {
  const shape = aggregateHeader(await reader.view(0, layout.prefix), type, layout);
  if (shape.properties > 0xffff) reader.warn("CodeView aggregate has unknown property bits.");
  if (layout.memberCountOffset === undefined) return { shape, end: layout.prefix };
  const count = await readLegacyCodeViewNumeric(reader, layout.memberCountOffset);
  if (count.value === undefined) reader.warn("CodeView aggregate member count is not an integer; its value is unavailable.");
  else {
    shape.memberCount = count.value;
    const value = BigInt(count.value);
    if (value < 0n || value > 0xffffffffffffffffn) {
      reader.warn("CodeView aggregate member count is outside the uint64 range.");
    }
  }
  return { shape, end: count.end };
};

const arrayHeader = (view: DataView, type: number): CodeViewCompositeShape => {
  const elementType = type === 3 ? view.getUint16(4, true) : view.getUint32(4, true);
  if (type === 0x151b) return { kind: "vector", elementType, count: view.getUint32(8, true) };
  if (type === 0x151c) return { kind: "matrix", elementType, rows: view.getUint32(8, true),
    columns: view.getUint32(12, true), majorStride: view.getUint32(16, true), attributes: view.getUint8(20) };
  return { kind: "array", elementType,
    indexType: type === 3 ? view.getUint16(6, true) : view.getUint32(8, true),
    ...(type === 0x1516 ? { stride: view.getUint32(12, true) } : {}) };
};

const readCompositeSize = async (reader: LegacyCodeViewReader,
  shape: CodeViewCompositeShape, offset: number): Promise<number> => {
  if (shape.kind === "aggregate" && shape.underlyingType !== undefined) return offset;
  const numeric = await readLegacyCodeViewNumeric(reader, offset);
  if (numeric.value === undefined) reader.warn("CodeView composite size is not an integer; its byte size is unavailable.");
  else {
    shape.size = numeric.value;
    if (BigInt(numeric.value) < 0n) reader.warn("CodeView composite has a negative byte size.");
  }
  return numeric.end;
};

const readIdentity = async (reader: LegacyCodeViewReader, type: number, offset: number,
  shape: CodeViewCompositeShape): Promise<{ name: string; uniqueName?: string }> => {
  if (type < 0x1500) return { name: (await reader.pascal(offset)).name };
  const { name, end } = await reader.utf8Name(offset);
  // CV_prop_t.hasuniquename appends an identity only to modern aggregate records.
  if (shape.kind !== "aggregate" || !(shape.properties & 0x200)) return { name };
  try { return { name, uniqueName: await reader.utf8(end) }; }
  catch (error) { reader.warn(`CodeView decorated type name: ${String(error)}`); return { name }; }
};

/** Stored dimensions, byte sizes and references; no external type namespace is inferred. */
export const readCodeViewCompositeType = async (
  reader: LegacyCodeViewReader, type: number
): Promise<LegacyCodeViewTypeRecord | undefined> => {
  const layout = AGGREGATES.get(type);
  const prefix = layout?.prefix ?? ARRAY_PREFIXES.get(type);
  if (prefix === undefined) return undefined;
  const frame = layout ? await readAggregate(reader, type, layout)
    : { shape: arrayHeader(await reader.view(0, prefix), type), end: prefix };
  const shape = frame.shape;
  if (shape.kind === "matrix" && shape.attributes & ~1) reader.warn("CodeView matrix has unknown attribute bits.");
  const offset = await readCompositeSize(reader, shape, frame.end);
  try { return { type, shape, ...await readIdentity(reader, type, offset, shape) }; }
  catch (error) { reader.warn(`CodeView type record: ${String(error)}`); return { type, shape }; }
};
