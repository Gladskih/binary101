import type { LegacyCodeViewTypeRecord } from "./legacy-codeview-type-records.js";
import type { CodeViewDimensions } from "./legacy-codeview-dimensions.js";

interface CodeViewIndexInteger { byteWidth: number; interpretation: "signed" | "unsigned" }
type ConstantDimensions = Extract<CodeViewDimensions, { kind: "constantDimensions" }>;
interface BoundsNamespace {
  indexed: ReadonlyMap<number, LegacyCodeViewTypeRecord | null>;
  decoded: WeakMap<ConstantDimensions, ConstantDimensions>;
}

// TIS 3.4: constants have the width of the index type, not LF_NUMERIC encoding.
// Open Watcom's unchanged producer writes the same fixed-width representation:
// https://github.com/open-watcom/open-watcom-v2/blob/e28568669775a7119f381f3b37d21745d8afcfb6/bld/cg/c/cvtypes.c#L949
// Primitive identities and widths: Microsoft cvinfo.h TYPE_ENUM_e.
const INTEGER_TYPES = new Map<number, CodeViewIndexInteger>([
  ...[0x10, 0x11, 0x12, 0x13, 0x14].map((type, index) => [type,
    { byteWidth: 2 ** index, interpretation: "signed" }] as const),
  ...[0x20, 0x21, 0x22, 0x23, 0x24].map((type, index) => [type,
    { byteWidth: 2 ** index, interpretation: "unsigned" }] as const),
  ...[0x68, 0x72, 0x74, 0x76, 0x78].map((type, index) => [type,
    { byteWidth: 2 ** index, interpretation: "signed" }] as const),
  ...[0x69, 0x73, 0x75, 0x77, 0x79].map((type, index) => [type,
    { byteWidth: 2 ** index, interpretation: "unsigned" }] as const)
]);

const localTypes = (records: readonly LegacyCodeViewTypeRecord[]) => {
  const indexed = new Map<number, LegacyCodeViewTypeRecord | null>();
  for (const record of records) {
    if (record.index !== undefined) indexed.set(record.index, indexed.has(record.index) ? null : record);
  }
  return indexed;
};

const linkedIndex = (record: LegacyCodeViewTypeRecord | null | undefined): number | undefined => {
  const shape = record?.shape;
  switch (shape?.kind) {
    case "alias": case "modifier": return shape.typeIndex;
    case "aggregate": return shape.underlyingType;
    default: return undefined;
  }
};

const indexInteger = (initial: number, indexed: ReadonlyMap<number, LegacyCodeViewTypeRecord | null>) => {
  const visited = new Set<number>();
  let index = initial;
  while (index >= 0x1000) {
    if (visited.has(index)) return undefined;
    visited.add(index);
    const next = linkedIndex(indexed.get(index));
    if (next === undefined) return undefined;
    index = next;
  }
  return INTEGER_TYPES.get(index);
};

const fixedInteger = (bytes: Uint8Array, offset: number, encoding: CodeViewIndexInteger): string => {
  let value = 0n;
  for (let index = encoding.byteWidth - 1; index >= 0; index--) value = value << 8n | BigInt(bytes[offset + index]!);
  return (encoding.interpretation === "signed" ? BigInt.asIntN(encoding.byteWidth * 8, value) : value).toString();
};

const decodeBounds = (shape: ConstantDimensions, bytes: Uint8Array, encoding: CodeViewIndexInteger,
  warn: (message: string) => void): ConstantDimensions => {
  const declared = shape.rank * (shape.boundKind === "lowerUpper" ? 2 : 1);
  const count = Math.min(declared, Math.floor(bytes.length / encoding.byteWidth));
  if (count < declared) warn("CodeView constant array dimensions have truncated bounds.");
  return { ...shape, bounds: { kind: "integers", values: Array.from({ length: count },
    (_, index) => fixedInteger(bytes, index * encoding.byteWidth, encoding)) } };
};

const resolvedShape = (shape: ConstantDimensions, namespace: BoundsNamespace,
  warn: (message: string) => void): ConstantDimensions => {
  const known = namespace.decoded.get(shape);
  if (known) return known;
  if (shape.bounds.kind !== "encoded") return shape;
  const encoding = indexInteger(shape.indexType, namespace.indexed);
  const resolved = encoding ? decodeBounds(shape, shape.bounds.bytes, encoding, warn) : shape;
  if (!encoding) warn(`CodeView constant array bounds have an unresolved or noninteger index type #${shape.indexType}.`);
  namespace.decoded.set(shape, resolved);
  return resolved;
};

/** Resolve forward aliases and enums after framing; preserve bytes when the integer type is unknown. */
export const resolveCodeViewConstantBounds = (records: LegacyCodeViewTypeRecord[],
  warn: (message: string) => void): LegacyCodeViewTypeRecord[] => {
  if (!records.some(record => record.shape?.kind === "constantDimensions")) return records;
  const indexed = localTypes(records);
  // Global OMF offsets can alias one stored shape. Decode it once per namespace.
  const local: BoundsNamespace = { indexed, decoded: new WeakMap() };
  const external: BoundsNamespace = { indexed: new Map(), decoded: new WeakMap() };
  return records.map(record => {
    const shape = record.shape;
    if (shape?.kind !== "constantDimensions") return record;
    const namespace = record.index !== undefined && indexed.get(record.index) === record ? local : external;
    return { ...record, shape: resolvedShape(shape, namespace, warn) };
  });
};
