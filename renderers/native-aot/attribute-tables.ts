import type { NativeAotReflectionScope, NativeAotReflectionType } from "../../analyzers/native-aot/format.js";
import type { NativeAotAttribute } from "../../analyzers/native-aot/native-format-attributes.js";
import { escapeHtml } from "../../html-utils.js";
import type { PagedSortableTableModel } from "../paged-sortable-table.js";
import { nativeAotConstantText } from "./constant-values.js";

interface AttributeOwner {
  assembly: string;
  name: string;
  kind: string;
  attributes: NativeAotAttribute[];
}

const typeOwners = (assembly: string, type: NativeAotReflectionType): AttributeOwner[] => {
  const name = type.namespace ? `${type.namespace}.${type.name}` : type.name;
  return [
    { assembly, name, kind: "Type", attributes: type.attributes ?? [] },
    ...(type.definition?.genericParameters ?? []).map(parameter => ({ assembly,
      name: `${name}<${parameter.name}>`, kind: "Type parameter", attributes: parameter.attributes ?? [] })),
    ...type.methods.flatMap(method => [
      { assembly, name: `${name}.${method.name}`, kind: "Method", attributes: method.attributes ?? [] },
      ...(method.parameters ?? []).map(parameter => ({ assembly,
        name: `${name}.${method.name}: ${parameter.sequence} ${parameter.name}`, kind: "Parameter",
        attributes: parameter.attributes ?? [] })),
      ...(method.genericParameters ?? []).map(parameter => ({ assembly,
        name: `${name}.${method.name}<${parameter.name}>`, kind: "Method type parameter", attributes: parameter.attributes ?? [] }))
    ]),
    ...type.fields.map(field => ({ assembly, name: `${name}.${field.name}`, kind: "Field", attributes: field.attributes ?? [] })),
    ...(type.definition?.properties ?? []).map(property => ({ assembly,
      name: `${name}.${property.name}`, kind: "Property", attributes: property.attributes ?? [] })),
    ...(type.definition?.events ?? []).map(event => ({ assembly,
      name: `${name}.${event.name}`, kind: "Event", attributes: event.attributes ?? [] }))
  ];
};

const scopeOwners = (scope: NativeAotReflectionScope): AttributeOwner[] => [
  { assembly: scope.name, name: scope.name, kind: "Assembly", attributes: scope.attributes ?? [] },
  { assembly: scope.name, name: scope.moduleName, kind: "Module", attributes: scope.moduleAttributes ?? [] },
  ...scope.types.flatMap(type => typeOwners(scope.name, type))
];

const attributeArguments = (attribute: NativeAotAttribute): string => [
  ...attribute.fixedArguments.map(nativeAotConstantText),
  ...attribute.namedArguments.map(argument =>
    `${argument.kind} ${argument.name}: ${argument.type} = ${nativeAotConstantText(argument.value)}`)
].join("; ");

export const createNativeAotAttributeTable = (scopes: NativeAotReflectionScope[]): PagedSortableTableModel => {
  const rows = scopes.flatMap(scopeOwners).flatMap(owner => owner.attributes.map(attribute =>
    [owner.assembly, owner.kind, owner.name, attribute.type, attributeArguments(attribute)]));
  return { id: "native-aot-custom-attributes", rowCount: rows.length, pageSize: 100,
    tableClassName: "nativeAotAttributesTable",
    columns: ["Assembly", "Applied to", "Owner", "Attribute", "Arguments"].map(label => ({ label })),
    rowAt: index => rows[index] ? { cells: rows[index]!.map(value => ({
      html: value ? escapeHtml(value) : "-", sortValue: value
    })) } : null,
    sortValueAt: (row, column) => rows[row]?.[column] ?? "" };
};
