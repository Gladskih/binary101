import type { LegacyCodeViewTypeRecord, LegacyCodeViewTypes } from "../../analyzers/pe/debug/legacy-codeview-type-records.js";
import type { CodeViewCompositeShape, CodeViewAggregate } from "../../analyzers/pe/debug/legacy-codeview-composite-records.js";
import type { CodeViewDimensions } from "../../analyzers/pe/debug/legacy-codeview-dimensions.js";
import { createCodeViewTypeFormatter, indexCodeViewTypes } from "./codeview-type-names.js";
import { legacyCodeViewHlslKindName, legacyCodeViewTypeName } from "./legacy-codeview-kinds.js";
import { createCodeViewFieldListResolver, type CodeViewFieldListResolution } from "./codeview-field-lists.js";

// CV_prop_t, CV_HFA_e and CV_MOCOM_UDT_e in Microsoft's cvinfo.h.
// https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h
const AGGREGATE_FLAGS: readonly [number, string][] = [[0, "packed"], [1, "constructors/destructors"],
  [2, "overloaded operators"], [3, "nested type"], [4, "contains nested types"], [5, "assignment operator"],
  [6, "conversion operators"], [7, "forward declaration"], [8, "scoped"], [9, "decorated name flag"],
  [10, "sealed"], [13, "intrinsic"]];
const OVERLOADED_METHODS = new Set([0x408, 0x1407, 0x150f]);
interface FieldListStatistics { records: number; members: bigint | undefined }
type TypeLayout = CodeViewCompositeShape | Extract<CodeViewDimensions, { kind: "dimensionedArray" }>;

const aggregateProperties = (properties: number): string => [
  ...AGGREGATE_FLAGS.filter(([bit]) => properties & 1 << bit).map(([, label]) => label),
  ["", "HFA: float", "HFA: double", "HFA: other"][properties >>> 11 & 3],
  ["", "MoCOM: reference", "MoCOM: value", "MoCOM: interface"][properties >>> 14 & 3],
  properties >>> 16 ? `unknown property bits 0x${((properties & ~0xffff) >>> 0).toString(16)}` : ""
].filter(Boolean).join("; ") || "none";

const compositeShape = (record: LegacyCodeViewTypeRecord): TypeLayout | undefined => {
  const shape = record.shape;
  switch (shape?.kind) {
    case "aggregate": case "array": case "vector": case "matrix": case "dimensionedArray": return shape;
    default: return undefined;
  }
};

const propertiesText = (shape: TypeLayout): string => {
  if (shape.kind === "aggregate") return aggregateProperties(shape.properties);
  if (shape.kind !== "matrix") return "none";
  return [shape.attributes & 1 ? "row-major" : "column-major",
    shape.attributes & ~1 ? `unknown attributes 0x${(shape.attributes & ~1).toString(16)}` : ""]
    .filter(Boolean).join("; ");
};

const fieldListStatistics = (resolved: CodeViewFieldListResolution): FieldListStatistics => {
  const statistics: FieldListStatistics = { records: 0, members: 0n };
  for (const list of resolved.lists) for (const field of list.members ?? []) {
    if (field.continuation !== undefined) continue;
    statistics.records++;
    if (statistics.members === undefined) continue;
    const count = OVERLOADED_METHODS.has(field.type) ? field.methodCount : 1;
    statistics.members = count === undefined ? undefined : statistics.members + BigInt(count);
  }
  return statistics;
};

const memberCountIssue = (members: bigint | undefined, declared: number | string | undefined): string => {
  const value = String(declared);
  return members !== undefined && /^\d+$/.test(value) && members > BigInt(value)
    ? "declared member count is too small" : "";
};

const fieldListSummary = (resolved: CodeViewFieldListResolution, declared: number | string | undefined): string => {
  const statistics = fieldListStatistics(resolved);
  return [resolved.lists.length ? `${statistics.records} ${statistics.records === 1 ? "record" : "records"}` +
    (resolved.lists.length > 1 ? ` in ${resolved.lists.length} lists` : "") : "", ...resolved.issues,
  memberCountIssue(statistics.members, declared)]
    .filter(Boolean).join("; ");
};

const aggregateReferences = (shape: CodeViewAggregate, format: (index: number) => string,
  resolve: ReturnType<typeof createCodeViewFieldListResolver>): string => [
  shape.fieldList ? `fields: ${fieldListSummary(resolve(shape.fieldList), shape.memberCount)}` : "",
  shape.derivedTypes ? `derived types: ${format(shape.derivedTypes)}` : "",
  shape.vtableShape ? `vtable shape: ${format(shape.vtableShape)}` : "",
  shape.underlyingType === undefined ? "" : `underlying type: ${format(shape.underlyingType)}`
].filter(Boolean).join("; ") || "none";

const relatedTypes = (shape: TypeLayout, format: (index: number) => string,
  resolve: ReturnType<typeof createCodeViewFieldListResolver>): string => {
  if (shape.kind === "aggregate") return aggregateReferences(shape, format, resolve);
  if (shape.kind === "dimensionedArray") return `underlying type: ${format(shape.underlyingType)}; ` +
    `bounds #${shape.dimensionsType}: ${format(shape.dimensionsType)}`;
  const element = `element: ${format(shape.elementType)}`;
  if (shape.kind === "vector") return `${element}; elements: ${shape.count}`;
  if (shape.kind === "matrix") return `${element}; rows: ${shape.rows}; columns: ${shape.columns}; ` +
    `major stride: ${shape.majorStride} bytes`;
  return `${element}; index: ${format(shape.indexType)}` +
    (shape.stride === undefined ? "" : `; stride: ${shape.stride} bytes`);
};

const byteSize = (shape: TypeLayout): string => {
  if (shape.kind === "dimensionedArray") return "not stored";
  return shape.kind === "aggregate" && shape.underlyingType !== undefined ? "—" : shape.size ?? "unavailable";
};

const metadata = (shape: TypeLayout | undefined,
  format: (index: number) => string, resolve: ReturnType<typeof createCodeViewFieldListResolver>): string[] => {
  if (!shape) return ["—", "—", "—", "—"];
  return [byteSize(shape),
    shape.kind === "aggregate" ? String(shape.memberCount ?? "unavailable") : "—",
    propertiesText(shape), relatedTypes(shape, format, resolve)];
};

/** Extend the existing named-type table; decorated identities stay separate and exact. */
export const codeViewTypeRows = (data: LegacyCodeViewTypes): string[][] => {
  const indexed = indexCodeViewTypes(data.records);
  const format = createCodeViewTypeFormatter(indexed);
  const resolve = createCodeViewFieldListResolver(indexed);
  const externalFormat = createCodeViewTypeFormatter(new Map());
  const externalResolve = createCodeViewFieldListResolver(new Map());
  return data.records.flatMap(record => {
    const shape = compositeShape(record);
    const kind = legacyCodeViewTypeName(record.type, data.encoding);
    const hlsl = record.shape?.kind === "hlsl" ? record.shape : undefined;
    const properties = hlsl?.properties.map((property, index) =>
      `property ${index + 1}: ${property.value ?? `numeric leaf 0x${property.leaf?.toString(16) ?? "unknown"}`}`).join("; ");
    const hlslRelated = hlsl ? [hlsl.subtypeIndex === 0 ? "no subtype" :
      `subtype: ${(record.index === undefined ? externalFormat : format)(hlsl.subtypeIndex)}`,
      `numeric properties decoded: ${hlsl.properties.length} / ${hlsl.propertyCount}`,
    hlsl.reservedBits ? `reserved bits: 0x${hlsl.reservedBits.toString(16)}` : ""]
      .filter(Boolean).join("; ") : undefined;
    const rows: string[][] = hlsl ? [[legacyCodeViewHlslKindName(hlsl.builtinKind),
      record.name || "(unnamed built-in type)", hlsl.byteSize?.value ?? "unavailable", "—",
      properties || "none", hlslRelated ?? "none"]] : record.name === undefined && !shape ? [] : [[kind,
      record.name === undefined ? "(name unavailable)" : record.name || "(unnamed)",
      ...metadata(shape, record.index === undefined ? externalFormat : format,
        record.index === undefined ? externalResolve : resolve)]];
    if (record.uniqueName !== undefined) rows.push([`${kind} (decorated)`, record.uniqueName, "—", "—", "—", "—"]);
    return rows;
  });
};
