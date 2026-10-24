import type { CodeViewC6ScalarBase, CodeViewC6Type } from "../../analyzers/pe/debug/codeview-c6-types.js";
import type { PeLegacyCodeViewInfo } from "../../analyzers/pe/debug/legacy-codeview.js";
import type { LegacyCodeViewTable } from "./legacy-codeview-tables.js";
import { legacyCodeViewTypeName } from "./legacy-codeview-kinds.js";

// C6 leaf identifiers have different meanings from modern CodeView primitive types.
// Microsoft C Developer's Toolkit 1.4, and cvdump/typeinfo.h at the pinned commit.
// https://www.pcjs.org/documents/books/mspl13/c/ctoolkit/
const SCALAR_STYLES = new Map([["108", "boolean"], ["111", "character"], ["112", "integer"],
  ["124", "unsigned integer"], ["125", "signed integer"], ["126", "real"]]);
const POINTER_STYLES = new Map([[90, "32-bit offset"], [94, "huge"], [115, "far"], [116, "near"]]);
const CALLING_CONVENTIONS = new Map([[99, "C near"], [100, "C far"], [115, "Pascal far"],
  [116, "Pascal near"], [149, "near fastcall"], [150, "far fastcall"]]);
const PACKING = new Map([[104, "packed"], [105, "unpacked"]]);

const baseName = (base: CodeViewC6ScalarBase): string => base.kind === "type"
  ? `type #${base.index}` : SCALAR_STYLES.get(base.value) ?? `style leaf ${base.value}`;

const scalarText = (shape: Extract<CodeViewC6Type, { kind: "scalar" }>): string => {
  const range = shape.range;
  return baseName(shape.base) + (range
    ? `; representation: ${baseName(range.base)}; range ${range.lower} to ${range.upper}` : "");
};

const structureText = (shape: Extract<CodeViewC6Type, { kind: "structure" }>): string => [
  `${shape.fieldCount} fields`,
  shape.typeList === undefined ? "" : `field types: list #${shape.typeList}`,
  shape.nameList === undefined ? "" : `field names: list #${shape.nameList}`,
  shape.packing === undefined ? "" : PACKING.get(shape.packing)
    ?? `unknown packing leaf ${shape.packing}`
].filter(Boolean).join("; ");

const callingConvention = (shape: Extract<CodeViewC6Type, { kind: "procedure" }>): string =>
  CALLING_CONVENTIONS.get(shape.callingConvention) ?? `unknown calling convention ${shape.callingConvention}`;

const procedureText = (shape: Extract<CodeViewC6Type, { kind: "procedure" }>): string => [
  callingConvention(shape),
  `${shape.parameterCount} parameters`, `arguments: type #${shape.argumentsType}`,
  shape.returnType === undefined ? `return marker ${shape.returnLeaf}` : `returns type #${shape.returnType}`
].join("; ");

const pointerStyle = (shape: Extract<CodeViewC6Type, { kind: "pointer" }>): string => shape.style === undefined
  ? "style not stored" : POINTER_STYLES.get(shape.style) ?? `unknown pointer style ${shape.style}`;

const arrayText = (shape: Extract<CodeViewC6Type, { kind: "array" }>): string =>
  `element: type #${shape.elementType}` + (shape.indexType === undefined ? "" : `; index: type #${shape.indexType}`);

const bitfieldText = (shape: Extract<CodeViewC6Type, { kind: "bitfield" }>): string =>
  `bit position ${shape.position}; ` + (SCALAR_STYLES.get(String(shape.style)) ?? `unknown signedness leaf ${shape.style}`);

const details = (shape: CodeViewC6Type): string => {
  switch (shape.kind) {
    case "array": return arrayText(shape);
    case "structure": return structureText(shape);
    case "scalar": return scalarText(shape);
    case "pointer": return `points to type #${shape.typeIndex}; ${pointerStyle(shape)}`;
    case "bitfield": return bitfieldText(shape);
    case "procedure": return procedureText(shape);
  }
};

const summary = (shape: CodeViewC6Type): string => {
  switch (shape.kind) {
    case "array": return shape.indexType === undefined ? "index type not stored" : "explicit index type";
    case "structure": return `${shape.fieldCount} fields`;
    case "scalar": return shape.base.kind === "style" ? baseName(shape.base) : "referenced base type";
    case "pointer": return pointerStyle(shape);
    case "bitfield": return bitfieldText(shape);
    case "procedure": return `${shape.parameterCount} parameters; ${callingConvention(shape)}`;
  }
};

interface C6TypeTableState {
  named: LegacyCodeViewTable;
  groups: Map<string, { row: string[]; count: number }>;
}

const addType = (state: C6TypeTableState, shape: CodeViewC6Type, recordType: number,
  name: string | undefined, directory: number, module: number): void => {
  const prefix = [String(directory), String(module), legacyCodeViewTypeName(recordType, "c6")];
  const bitSize = "bitLength" in shape ? shape.bitLength : "not stored";
  if (name !== undefined) state.named.rows.push([...prefix, name, bitSize, details(shape)]);
  const row = [...prefix, bitSize, summary(shape)];
  const key = JSON.stringify(row);
  const group = state.groups.get(key) ?? { row, count: 0 };
  group.count++;
  state.groups.set(key, group);
};

export const buildCodeViewC6TypeTables = (info: PeLegacyCodeViewInfo): LegacyCodeViewTable[] => {
  const table: LegacyCodeViewTable = { key: "legacyTypeDetails", title: "C6 type sizes and relationships",
    columns: ["Directory", "Module", "Type", "Name", "Bit size", "Properties"], rows: [] };
  const state: C6TypeTableState = { named: table, groups: new Map() };
  info.directories.forEach((directory, position) => {
    for (const section of directory.subsections) {
      const data = section.data;
      if (data?.kind !== "types" || data.encoding !== "c6") continue;
      for (const record of data.records) {
        const shape = record.c6;
        if (!shape) continue;
        addType(state, shape, record.type, record.name, position + 1, section.module);
      }
    }
  });
  return [{ key: "legacyTypeStatistics", title: "C6 type layout statistics",
    columns: ["Directory", "Module", "Type", "Bit size", "Properties", "Records"],
    rows: [...state.groups.values()].map(group => [...group.row, String(group.count)]) }, table]
    .filter(value => value.rows.length);
};
