import type { PeLegacyCodeViewInfo } from "../../analyzers/pe/debug/legacy-codeview.js";
import type { LegacyCodeViewTable } from "./legacy-codeview-tables.js";
import type { LegacyCodeViewTypeRecord, LegacyCodeViewTypes } from "../../analyzers/pe/debug/legacy-codeview-type-records.js";
import type { CodeViewDimensions } from "../../analyzers/pe/debug/legacy-codeview-dimensions.js";
import { indexCodeViewTypes, createCodeViewTypeFormatter } from "./codeview-type-names.js";
import { legacyCodeViewSymbolName } from "./legacy-codeview-kinds.js";

type Dimensions = Extract<CodeViewDimensions, { kind: "constantDimensions" | "variableDimensions" }>;

const dimensionOwners = (records: readonly LegacyCodeViewTypeRecord[],
  indexed: ReadonlyMap<number, LegacyCodeViewTypeRecord | null>): Map<LegacyCodeViewTypeRecord, Set<string>> => {
  const owners = new Map<LegacyCodeViewTypeRecord, Set<string>>();
  for (const record of records) {
    if (record.index === undefined || indexed.get(record.index) !== record) continue;
    const shape = record.shape;
    if (shape?.kind !== "dimensionedArray") continue;
    const dimensions = indexed.get(shape.dimensionsType);
    if (!dimensions) continue;
    const names = owners.get(dimensions) ?? new Set<string>();
    names.add(record.name || `array type #${record.index}`);
    owners.set(dimensions, names);
  }
  return owners;
};

const boundReference = (index: number, indexed: ReadonlyMap<number, LegacyCodeViewTypeRecord | null>,
  format: (index: number) => string): string => {
  if (index === 3) return "(unspecified)"; // lfDimVar permits T_VOID in place of a reference.
  const record = indexed.get(index);
  if (!record) return format(index);
  if (record.type !== 0x20c) return `invalid bound reference: ${format(index)}`;
  const symbol = record.symbols?.[0];
  return symbol?.name || (symbol ? `${legacyCodeViewSymbolName(symbol.type)} (unnamed)` : "unavailable bound symbol");
};

const boundValues = (shape: Dimensions, indexed: ReadonlyMap<number, LegacyCodeViewTypeRecord | null>,
  format: (index: number) => string): readonly string[] => {
  if (shape.kind === "variableDimensions") return shape.bounds.map(index => boundReference(index, indexed, format));
  return shape.bounds.kind === "integers" ? shape.bounds.values : [];
};

const ownerName = (record: LegacyCodeViewTypeRecord, names: ReadonlySet<string> | undefined): string => {
  const fallback = `dimensions #${record.index ?? "unresolved"}`;
  if (!names?.size) return fallback;
  return names.size === 1 ? [...names][0]! : `${fallback} (arrays: ${names.size})`;
};

const dimensionRows = (shape: Dimensions, name: string, values: readonly string[], indexType: string): string[][] => {
  const stride = shape.boundKind === "lowerUpper" ? 2 : 1;
  const owner = `${name} (rank: ${shape.rank})`;
  if (!values.length) return shape.rank ? [[owner, indexType, "—", "unavailable", "unavailable"]] : [];
  return Array.from({ length: Math.ceil(values.length / stride) }, (_, index) => [owner, indexType, String(index + 1),
    stride === 2 ? values[index * stride]! : "(language default)", values[index * stride + stride - 1] ?? "unavailable"]);
};

const arrayRows = (data: LegacyCodeViewTypes): string[][] => {
  const indexed = indexCodeViewTypes(data.records);
  const owners = dimensionOwners(data.records, indexed);
  const format = createCodeViewTypeFormatter(indexed);
  const external = new Map<number, LegacyCodeViewTypeRecord>();
  const externalFormat = createCodeViewTypeFormatter(external);
  return data.records.flatMap(record => {
    const shape = record.shape;
    if (shape?.kind !== "constantDimensions" && shape?.kind !== "variableDimensions") return [];
    const local = record.index !== undefined && indexed.get(record.index) === record;
    return dimensionRows(shape, ownerName(record, owners.get(record)),
      boundValues(shape, local ? indexed : external, local ? format : externalFormat),
      (local ? format : externalFormat)(shape.indexType));
  });
};

export const buildCodeViewArrayBounds = (info: PeLegacyCodeViewInfo): LegacyCodeViewTable[] => {
  const table: LegacyCodeViewTable = { key: "arrayBounds", title: "Array bounds",
    columns: ["Directory", "Module", "Array / dimensions", "Index type", "Dimension", "Lower bound", "Upper bound"], rows: [] };
  info.directories.forEach((directory, index) => {
    for (const section of directory.subsections) {
      if (section.data?.kind !== "types" || section.data.encoding) continue;
      for (const row of arrayRows(section.data)) table.rows.push([String(index + 1), String(section.module), ...row]);
    }
  });
  return table.rows.length ? [table] : [];
};
