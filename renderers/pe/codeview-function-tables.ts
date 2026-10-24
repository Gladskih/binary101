import type { PeLegacyCodeViewInfo } from "../../analyzers/pe/debug/legacy-codeview.js";
import type { LegacyCodeViewTypeRecord, LegacyCodeViewTypes } from "../../analyzers/pe/debug/legacy-codeview-type-records.js";
import type { CodeViewTypeShape } from "../../analyzers/pe/debug/legacy-codeview-type-shapes.js";
import type { LegacyCodeViewTable } from "./legacy-codeview-tables.js";
import { createCodeViewTypeFormatter, indexCodeViewTypes } from "./codeview-type-names.js";
import { codeViewMethodNames, type CodeViewFunctionName } from "./codeview-method-names.js";
import { codeViewMemberAttributes } from "./codeview-member-attributes.js";

type Procedure = Extract<CodeViewTypeShape, { kind: "procedure" | "memberFunction" }>;
type FunctionId = Extract<CodeViewTypeShape, { kind: "functionId" | "memberFunctionId" }>;

const isProcedure = (shape: CodeViewTypeShape | undefined): shape is Procedure =>
  shape?.kind === "procedure" || shape?.kind === "memberFunction";

const isFunctionId = (shape: CodeViewTypeShape | undefined): shape is FunctionId =>
  shape?.kind === "functionId" || shape?.kind === "memberFunctionId";

const isLocalRecord = (record: LegacyCodeViewTypeRecord,
  indexed: ReadonlyMap<number, LegacyCodeViewTypeRecord | null>): boolean =>
  record.index !== undefined && indexed.get(record.index) === record;

// CV_call_e values retain source conventions rather than guessing from machine type.
// https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvconst.h
const CALLING_CONVENTIONS = ["cdecl (near)", "cdecl (far)", "Pascal (near)", "Pascal (far)",
  "fastcall (near)", "fastcall (far)", "reserved", "stdcall (near)", "stdcall (far)",
  "syscall (near)", "syscall (far)", "thiscall", "MIPS", "generic", "Alpha", "PowerPC", "SuperH",
  "ARM", "AM33", "TriCore", "SuperH-5", "M32R", "CLR", "always inline", "vectorcall"];

const procedureProperties = (procedure: Procedure, format: (index: number) => string): string => [
  procedure.attributes & 1 ? "C++ UDT return" : "", procedure.attributes & 2 ? "constructor" : "",
  procedure.attributes & 4 ? "constructor with virtual bases" : "",
  procedure.attributes & ~7 ? `unknown attributes 0x${(procedure.attributes & ~7).toString(16)}` : "",
  procedure.kind === "memberFunction" ? `class ${format(procedure.classType)}; this: ${format(procedure.thisType)}; ` +
    `this adjustment: ${procedure.thisAdjustment} bytes` : ""
].filter(Boolean).join("; ") || "none";

const argumentText = (procedure: Procedure, indexed: ReadonlyMap<number, LegacyCodeViewTypeRecord | null>,
  format: (index: number) => string): string => {
  const argumentsRecord = indexed.get(procedure.argumentList)?.shape;
  if (argumentsRecord?.kind !== "arguments") return `unresolved argument list #${procedure.argumentList}`;
  const types = argumentsRecord.types;
  const text = types.map((index, position) => index === 0 && position === types.length - 1 ? "..." : format(index)).join(", ");
  return text || "(no parameters)";
};

const functionLabel = (record: LegacyCodeViewTypeRecord, format: (index: number) => string): string => {
  const name = record.strings?.[0] || "(unnamed function)";
  const shape = record.shape;
  if (shape?.kind === "memberFunctionId") return `${format(shape.classType)}::${name}`;
  return shape?.kind === "functionId" && shape.scopeId ? `scope #${shape.scopeId}::${name}` : name;
};

const functionNames = (records: readonly LegacyCodeViewTypeRecord[],
  indexed: ReadonlyMap<number, LegacyCodeViewTypeRecord | null>,
  format: (index: number) => string): ReadonlyMap<number, CodeViewFunctionName[]> => {
  const names = codeViewMethodNames(records, indexed, format);
  for (const record of records) {
    const shape = record.shape;
    if (!isFunctionId(shape) || !isLocalRecord(record, indexed)) continue;
    const group = names.get(shape.functionType) ?? [];
    const name = functionLabel(record, format);
    if (!group.some(known => known.name === name)) group.push({ name });
    names.set(shape.functionType, group);
  }
  return names;
};

const unresolvedFunctions = (records: readonly LegacyCodeViewTypeRecord[],
  indexed: ReadonlyMap<number, LegacyCodeViewTypeRecord | null>,
  names: ReadonlyMap<number, CodeViewFunctionName[]>): string[][] => {
  const externalFormat = createCodeViewTypeFormatter(new Map());
  const external = records.flatMap(record => !isLocalRecord(record, indexed) && isFunctionId(record.shape)
    ? [[functionLabel(record, externalFormat), `unresolved function type #${record.shape.functionType}`,
      "unknown", "unknown", "unknown", "External, unresolved, or ambiguous type namespace."]] : []);
  const missing = [...names].flatMap(([index, labels]) => isProcedure(indexed.get(index)?.shape) ? []
    : labels.map(label => [label.name, `unresolved function type #${index}`, "unknown", "unknown", "unknown",
      "Function type is missing, ambiguous, or not callable."]));
  return [...missing, ...external];
};

const namedProperties = (procedure: Procedure, label: CodeViewFunctionName,
  format: (index: number) => string): string => {
  const properties = procedureProperties(procedure, format);
  return [properties === "none" ? "" : properties,
    label.attributes === undefined ? "" : codeViewMemberAttributes(label.attributes).join("; "),
    label.vtableOffset === undefined ? "" : `vtable offset: ${label.vtableOffset} bytes`]
    .filter(Boolean).join("; ") || "none";
};

const functionRows = (data: LegacyCodeViewTypes): string[][] => {
  const indexed = indexCodeViewTypes(data.records);
  const format = createCodeViewTypeFormatter(indexed);
  const names = functionNames(data.records, indexed, format);
  const externalIndexed = new Map<number, LegacyCodeViewTypeRecord>();
  const externalFormat = createCodeViewTypeFormatter(externalIndexed);
  const rows = data.records.flatMap(record => {
    const shape = record.shape;
    if (!isProcedure(shape)) return [];
    const labels = record.index === undefined ? [{ name: "Unresolved function type" }] :
      indexed.get(record.index) !== record ? [{ name: `Ambiguous function type #${record.index}` }] :
        names.get(record.index) ?? [{ name: `Function type #${record.index}` }];
    const localFormat = record.index === undefined ? externalFormat : format;
    return labels.map(label => [label.name, localFormat(shape.returnType),
      argumentText(shape, record.index === undefined ? externalIndexed : indexed, localFormat),
      String(shape.parameterCount),
      CALLING_CONVENTIONS[shape.callingConvention] ?? `unknown convention ${shape.callingConvention}`,
      namedProperties(shape, label, localFormat)]);
  });
  return [...rows, ...unresolvedFunctions(data.records, indexed, names)];
};

export const buildCodeViewFunctionTables = (info: PeLegacyCodeViewInfo): LegacyCodeViewTable[] => {
  const table: LegacyCodeViewTable = { key: "functions", title: "Function type signatures",
    columns: ["Directory", "Module", "Function / type", "Return type", "Parameters",
      "Declared parameters", "Calling convention", "Properties"], rows: [] };
  info.directories.forEach((directory, index) => {
    for (const section of directory.subsections) {
      if (section.data?.kind !== "types" || section.data.encoding) continue;
      for (const row of functionRows(section.data)) {
        table.rows.push([String(index + 1), String(section.module), ...row]);
      }
    }
  });
  return table.rows.length ? [table] : [];
};
