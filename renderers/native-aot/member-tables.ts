import type {
  NativeAotGenericParameter, NativeAotReflectionScope, NativeAotReflectionType
} from "../../analyzers/native-aot/format.js";
import { escapeHtml } from "../../html-utils.js";
import type { PagedSortableTableModel } from "../paged-sortable-table.js";
import { nativeAotFieldSignature, nativeAotMethodSignature } from "./member-signatures.js";

const genericParameters = (parameters: NativeAotGenericParameter[]): string =>
  parameters.map(parameter => `${parameter.name} (#${parameter.number}, ` +
    `flags=0x${parameter.flags.toString(16)}, kind=${parameter.kind}` +
    `${parameter.constraints.length ? `, ${parameter.constraints.join(" & ")}` : ""})`).join("; ");

const typeName = (type: NativeAotReflectionType): string =>
  type.namespace ? `${type.namespace}.${type.name}` : type.name;

const typeRows = (scope: NativeAotReflectionScope): string[][] =>
  scope.types.flatMap(type => type.definition ? [[scope.name, typeName(type),
    `0x${type.definition.flags.toString(16)}`, type.definition.baseType,
    type.definition.interfaces.join(", "), String(type.definition.size),
    String(type.definition.packingSize), genericParameters(type.definition.genericParameters)]] : []);

const memberRows = (scope: NativeAotReflectionScope, type: NativeAotReflectionType): string[][] => {
  const owner = [scope.name, typeName(type)];
  return [
    ...type.methods.map(method => [...owner, "Method", method.name,
      nativeAotMethodSignature(method), method.flags == null ? "" : `0x${method.flags.toString(16)}`,
      [method.implementationFlags == null ? "" : `impl=0x${method.implementationFlags.toString(16)}`,
        method.signature ? `cc=0x${method.signature.callingConvention.toString(16)}` : "",
        method.parameters?.map(parameter => `${parameter.sequence}: ${parameter.name} ` +
          `(flags=0x${parameter.flags.toString(16)})`).join("; ") ?? "",
        genericParameters(method.genericParameters ?? [])].filter(Boolean).join("; ")]),
    ...type.fields.map(field => [...owner, "Field", field.name, nativeAotFieldSignature(field),
      field.flags == null ? "" : `0x${field.flags.toString(16)}`,
      field.offset == null ? "" : `offset=${field.offset}`]),
    ...(type.definition?.properties ?? []).map(property => [...owner, "Property", property.name,
      `${property.type ?? "?"} (${property.parameters?.join(", ") ?? ""})`,
      property.flags == null ? "" : `0x${property.flags.toString(16)}`,
      property.semantics?.map(item => `${item.method} (0x${item.attributes.toString(16)})`)
        .join("; ") ?? ""]),
    ...(type.definition?.events ?? []).map(event => [...owner, "Event", event.name,
      event.type ?? "?", event.flags == null ? "" : `0x${event.flags.toString(16)}`,
      event.semantics?.map(item => `${item.method} (0x${item.attributes.toString(16)})`)
        .join("; ") ?? ""])
  ];
};

const tableModel = (id: string, columns: string[], rows: string[][]): PagedSortableTableModel => ({
  id, columns: columns.map(label => ({ label,
    className: ["Flags", "Size", "Packing"].includes(label) ? "peNumeric" : "" })),
  rowCount: rows.length,
  pageSize: 100, // Display pagination does not limit metadata parsing.
  tableClassName: "nativeAotDetailsTable",
  rowAt: index => rows[index] ? {
    cells: rows[index]!.map((value, column) => ({
      html: value ? escapeHtml(value) : "-", sortValue: value,
      className: ["Flags", "Size", "Packing"].includes(columns[column]!) ? "peNumeric" : ""
    }))
  } : null,
  sortValueAt: (row, column) => rows[row]?.[column] ?? ""
});

export const createNativeAotDefinitionTable = (
  scopes: NativeAotReflectionScope[]
): PagedSortableTableModel => tableModel("native-aot-type-definitions",
  ["Assembly", "Type", "Flags", "Base type", "Interfaces", "Size", "Packing", "Generic parameters"],
  scopes.flatMap(typeRows));

export const createNativeAotMemberTable = (
  scopes: NativeAotReflectionScope[]
): PagedSortableTableModel => tableModel("native-aot-member-definitions",
  ["Assembly", "Type", "Kind", "Name", "Signature", "Flags", "Metadata"],
  scopes.flatMap(scope => scope.types.flatMap(type => memberRows(scope, type))));

export const getNativeAotDefinitionTable = (
  scopes: NativeAotReflectionScope[], id: string
): PagedSortableTableModel | null => {
  if (id === "native-aot-type-definitions") return createNativeAotDefinitionTable(scopes);
  return id === "native-aot-member-definitions" ? createNativeAotMemberTable(scopes) : null;
};
