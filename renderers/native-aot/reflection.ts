"use strict";

import { escapeHtml } from "../../html-utils.js";
import type {
  NativeAotReflectionMetadata,
  NativeAotReflectionScope,
  NativeAotReflectionType
} from "../../analyzers/native-aot/format.js";
import {
  renderAutoPagedSortableTable,
  type PagedSortableTableCell,
  type PagedSortableTableModel
} from "../paged-sortable-table.js";

const NATIVE_AOT_REFLECTION_TYPES_TABLE_ID = "native-aot-reflection-types";

const scopeVersion = (scope: NativeAotReflectionScope): string => {
  const version = scope.version;
  return `${version.major}.${version.minor}.${version.build}.${version.revision}`;
};

const methodCount = (scope: NativeAotReflectionScope): number =>
  scope.types.reduce((count, type) => count + type.methods.length, 0);

const renderScopes = (scopes: NativeAotReflectionScope[]): string => {
  if (!scopes.length) return "";
  const rows = scopes.map(scope => `<tr><td>${escapeHtml(scope.name)}</td>` +
    `<td>${escapeHtml(scope.moduleName)}</td>` +
    `<td class="nativeAotTable__compact">${scopeVersion(scope)}</td>` +
    `<td class="nativeAotTable__compact peNumeric">${scope.types.length}</td>` +
    `<td class="nativeAotTable__compact peNumeric">${methodCount(scope)}</td></tr>`).join("");
  return `<h4>Reflection scopes</h4>` +
    `<p class="smallNote">A scope identifies one managed assembly and module represented in ` +
    `the NativeFormat blob. Counts cover only definitions retained for runtime reflection, not ` +
    `everything compiled into the executable.</p><div class="tableWrap">` +
    `<table class="table nativeAotScopesTable"><thead><tr>` +
    `<th>Assembly</th><th>Module</th>` +
    `<th class="nativeAotTable__compact">Assembly version</th>` +
    `<th class="nativeAotTable__compact peNumeric">Types</th>` +
    `<th class="nativeAotTable__compact peNumeric">Methods</th></tr></thead>` +
    `<tbody>${rows}</tbody></table></div>`;
};

const qualifiedTypeName = (type: NativeAotReflectionType): string =>
  type.namespace ? `${type.namespace}.${type.name}` : type.name;

const typeTableCells = (
  scope: NativeAotReflectionScope,
  type: NativeAotReflectionType
): PagedSortableTableCell[] => {
  const qualifiedName = qualifiedTypeName(type);
  const methodNames = type.methods.join(", ");
  return [{
    className: "nativeAotTypesTable__identity",
    html: escapeHtml(scope.name),
    sortValue: scope.name
  }, {
    className: "nativeAotTypesTable__identity",
    html: escapeHtml(qualifiedName),
    sortValue: qualifiedName
  }, {
    className: "nativeAotTypesTable__methods",
    html: methodNames ? escapeHtml(methodNames) : "-",
    sortValue: methodNames
  }];
};

export const createNativeAotReflectionTypeTableModel = (
  scopes: NativeAotReflectionScope[]
): PagedSortableTableModel => {
  const rows = scopes.flatMap(scope => scope.types.map(type => typeTableCells(scope, type)));
  return {
    id: NATIVE_AOT_REFLECTION_TYPES_TABLE_ID,
    pageSize: 100, // UI page size, not a NativeFormat analysis limit.
    rowCount: rows.length,
    tableClassName: "nativeAotTypesTable",
    columns: [
      { className: "nativeAotTypesTable__identity", label: "Assembly" },
      { className: "nativeAotTypesTable__identity", label: "Type" },
      { className: "nativeAotTypesTable__methods", label: "Methods" }
    ],
    rowAt: index => {
      const cells = rows[index];
      return cells ? { cells } : null;
    },
    sortValueAt: (rowIndex, columnIndex) => rows[rowIndex]?.[columnIndex]?.sortValue ?? ""
  };
};

export const getNativeAotReflectionTypeTableModel = (
  metadata: NativeAotReflectionMetadata | undefined,
  tableId: string
): PagedSortableTableModel | null =>
  metadata && tableId === NATIVE_AOT_REFLECTION_TYPES_TABLE_ID
    ? createNativeAotReflectionTypeTableModel(metadata.scopes)
    : null;

const renderTypes = (scopes: NativeAotReflectionScope[]): string => {
  const model = createNativeAotReflectionTypeTableModel(scopes);
  if (!model.rowCount) return "";
  return `<h4>Reflected types and methods</h4>` +
    `<p class="smallNote">Type names include their namespace and enclosing type. Method names ` +
    `do not include signatures or code addresses. Missing names may have been trimmed, so an ` +
    `empty list does not mean that the type has no native methods.</p>` +
    renderAutoPagedSortableTable(model);
};

const renderWarnings = (warnings: string[] | undefined): string => {
  if (!warnings?.length) return "";
  const items = warnings.map(warning => `<li>${escapeHtml(warning)}</li>`).join("");
  return `<h4>Warnings</h4><ul class="issueList">${items}</ul>`;
};

export const renderNativeAotReflection = (
  metadata: NativeAotReflectionMetadata
): string => renderScopes(metadata.scopes) + renderTypes(metadata.scopes) +
  renderWarnings(metadata.warnings);
