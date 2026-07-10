"use strict";

import { hex, hex64 } from "../../binary-utils.js";
import { escapeHtml } from "../../html-utils.js";
import type { PeWindowsParseResult } from "../../analyzers/pe/core/parse-result.js";
import {
  BASE_CLASS_ATTRIBUTES,
  BASE_CLASS_KNOWN_ATTRIBUTES,
  CLASS_HIERARCHY_ATTRIBUTES,
  CLASS_HIERARCHY_KNOWN_ATTRIBUTES,
  MAX_BASE_CLASS_DESCRIPTORS
} from "../../analyzers/pe/msvc-rtti/layout.js";
import type {
  MsvcRttiBaseClass,
  MsvcRttiClassHierarchy,
  MsvcRttiVftable
} from "../../analyzers/pe/msvc-rtti/types.js";
import {
  renderAutoPagedSortableTable,
  type PagedSortableTableCell,
  type PagedSortableTableModel
} from "../paged-sortable-table.js";

type AttributeDefinition = readonly [bit: number, label: string];
type BaseRow = { node: MsvcRttiBaseClass; depth: number };

const HIERARCHY_ATTRIBUTES: readonly AttributeDefinition[] = [
  [CLASS_HIERARCHY_ATTRIBUTES.multipleInheritance, "multiple inheritance"],
  [CLASS_HIERARCHY_ATTRIBUTES.virtualInheritance, "virtual inheritance"],
  [CLASS_HIERARCHY_ATTRIBUTES.ambiguous, "ambiguous"]
];

const BASE_ATTRIBUTES: readonly AttributeDefinition[] = [
  [BASE_CLASS_ATTRIBUTES.notVisible, "not visible"],
  [BASE_CLASS_ATTRIBUTES.ambiguous, "ambiguous"],
  [BASE_CLASS_ATTRIBUTES.privateOrProtectedBase, "private/protected base"],
  [
    BASE_CLASS_ATTRIBUTES.privateOrProtectedInCompleteObject,
    "private/protected in complete object"
  ],
  [BASE_CLASS_ATTRIBUTES.virtualBaseOfCompleteObject, "virtual base of complete object"],
  [BASE_CLASS_ATTRIBUTES.nonPolymorphic, "non-polymorphic"],
  [BASE_CLASS_ATTRIBUTES.hasClassHierarchyDescriptor, "additional class hierarchy"]
];

const formatAttributes = (
  attributes: number,
  definitions: readonly AttributeDefinition[],
  knownMask: number
): string => {
  const normalized = attributes >>> 0;
  const labels = definitions
    .filter(([bit]) => (normalized & bit) !== 0)
    .map(([, label]) => label);
  const unknown = (normalized & ~knownMask) >>> 0;
  if (unknown) labels.push(`unknown ${hex(unknown, 8)}`);
  return labels.length ? labels.join(", ") : "none";
};

export const formatMsvcRttiHierarchyAttributes = (attributes: number): string =>
  formatAttributes(attributes, HIERARCHY_ATTRIBUTES, CLASS_HIERARCHY_KNOWN_ATTRIBUTES);

export const formatMsvcRttiBaseAttributes = (attributes: number): string =>
  formatAttributes(attributes, BASE_ATTRIBUTES, BASE_CLASS_KNOWN_ATTRIBUTES);

export const formatMsvcRttiRva = (rva: number): string => hex(rva, 8);

export const formatMsvcRttiVa = (imageBase: bigint, rva: number): string =>
  hex64(imageBase + BigInt(rva));

const flattenHierarchy = (hierarchy: MsvcRttiClassHierarchy | null): BaseRow[] => {
  if (!hierarchy) return [];
  const rows: BaseRow[] = [];
  const pending: BaseRow[] = [{ node: hierarchy.root, depth: 0 }];
  while (pending.length && rows.length < MAX_BASE_CLASS_DESCRIPTORS) {
    const current = pending.pop();
    if (!current) break;
    rows.push(current);
    for (let index = current.node.children.length - 1; index >= 0; index -= 1) {
      const child = current.node.children[index];
      if (child) pending.push({ node: child, depth: current.depth + 1 });
    }
  }
  return rows;
};

const resolveHierarchy = (
  pe: PeWindowsParseResult,
  vftable: MsvcRttiVftable
): MsvcRttiClassHierarchy | null => {
  const locator = pe.msvcRtti?.completeObjectLocators.find(
    entry => entry.rva === vftable.completeObjectLocatorRva
  );
  return pe.msvcRtti?.classHierarchies.find(
    hierarchy => hierarchy.rva === locator?.classHierarchyDescriptorRva
  ) ?? null;
};

const baseCells = (
  pe: PeWindowsParseResult,
  row: BaseRow
): PagedSortableTableCell[] => {
  const decoratedName = pe.msvcRtti?.types.find(
    type => type.rva === row.node.typeDescriptorRva
  )?.decoratedName ?? "(unresolved)";
  return [
    { html: `<code>${escapeHtml(decoratedName)}</code>`, sortValue: decoratedName },
    { className: "peNumeric", html: String(row.depth), sortValue: String(row.depth) },
    {
      className: "peNumeric",
      html: String(row.node.numContainedBases),
      sortValue: String(row.node.numContainedBases)
    },
    { className: "peNumeric", html: String(row.node.pmd.mdisp), sortValue: String(row.node.pmd.mdisp) },
    { className: "peNumeric", html: String(row.node.pmd.pdisp), sortValue: String(row.node.pmd.pdisp) },
    { className: "peNumeric", html: String(row.node.pmd.vdisp), sortValue: String(row.node.pmd.vdisp) },
    {
      html: escapeHtml(formatMsvcRttiBaseAttributes(row.node.attributes)),
      sortValue: formatMsvcRttiBaseAttributes(row.node.attributes)
    }
  ];
};

const createBaseTableModel = (
  pe: PeWindowsParseResult,
  vftable: MsvcRttiVftable,
  tableId: string
): PagedSortableTableModel => {
  const rows = flattenHierarchy(resolveHierarchy(pe, vftable));
  return {
    id: tableId,
    pageSize: 250, // UI page size, not an ABI limit.
    rowCount: rows.length,
    columns: [
      { label: "Decorated type name" },
      { className: "peNumeric", label: "Depth" },
      { className: "peNumeric", label: "Contained bases" },
      { className: "peNumeric", label: "mdisp" },
      { className: "peNumeric", label: "pdisp" },
      { className: "peNumeric", label: "vdisp" },
      { label: "Attributes" }
    ],
    rowAt: index => rows[index] ? { cells: baseCells(pe, rows[index]!) } : null,
    sortValueAt: (rowIndex, columnIndex) =>
      rows[rowIndex] ? baseCells(pe, rows[rowIndex]!)[columnIndex]?.sortValue ?? "" : ""
  };
};

const slotCells = (
  pe: PeWindowsParseResult,
  targetRva: number,
  index: number,
  symbolNames: ReadonlyMap<number, readonly string[]>
): PagedSortableTableCell[] => {
  const names = symbolNames.get(targetRva)?.join(", ") ?? "";
  return [
    { className: "peNumeric", html: String(index), sortValue: String(index) },
    {
      className: "peNumeric",
      html: formatMsvcRttiVa(pe.opt.ImageBase, targetRva),
      sortValue: String(targetRva)
    },
    {
      className: "peNumeric",
      html: formatMsvcRttiRva(targetRva),
      sortValue: String(targetRva)
    },
    { html: names ? escapeHtml(names) : `<span class="dim">-</span>`, sortValue: names }
  ];
};

const createSlotTableModel = (
  pe: PeWindowsParseResult,
  vftable: MsvcRttiVftable,
  tableId: string,
  symbolNames: ReadonlyMap<number, readonly string[]>
): PagedSortableTableModel => ({
  id: tableId,
  pageSize: 250, // UI page size, not an ABI limit.
  rowCount: vftable.functionTargetRvas.length,
  columns: [
    { className: "peNumeric", label: "Index" },
    { className: "peNumeric", label: "Function target VA" },
    { className: "peNumeric", label: "Function target RVA" },
    { label: "Known symbol" }
  ],
  rowAt: index => vftable.functionTargetRvas[index] == null
    ? null
    : { cells: slotCells(pe, vftable.functionTargetRvas[index], index, symbolNames) },
  sortValueAt: (rowIndex, columnIndex) => vftable.functionTargetRvas[rowIndex] == null
    ? ""
    : slotCells(pe, vftable.functionTargetRvas[rowIndex], rowIndex, symbolNames)[columnIndex]
      ?.sortValue ?? ""
});

const detailTableId = (vftableIndex: number, kind: "bases" | "slots"): string =>
  `pe-msvc-rtti-vftable-${vftableIndex}-${kind}`;

export const getMsvcRttiBaseDescriptorCount = (
  pe: PeWindowsParseResult,
  vftable: MsvcRttiVftable
): number => flattenHierarchy(resolveHierarchy(pe, vftable)).length;

export const renderMsvcRttiVftableDetails = (
  pe: PeWindowsParseResult,
  vftableIndex: number,
  symbolNames: ReadonlyMap<number, readonly string[]>
): string => {
  const vftable = pe.msvcRtti?.vftables[vftableIndex];
  if (!vftable) return "";
  const bases = createBaseTableModel(pe, vftable, detailTableId(vftableIndex, "bases"));
  const slots = createSlotTableModel(
    pe,
    vftable,
    detailTableId(vftableIndex, "slots"),
    symbolNames
  );
  return `<details><summary>Show inheritance and ${vftable.functionTargetRvas.length} vftable slot(s)</summary>` +
    `<h4>Base classes (preorder)</h4>${renderAutoPagedSortableTable(bases)}` +
    `<h4>vftable slots</h4>${renderAutoPagedSortableTable(slots)}</details>`;
};

export const getMsvcRttiDetailTableModel = (
  pe: PeWindowsParseResult,
  tableId: string,
  symbolNames: ReadonlyMap<number, readonly string[]>
): PagedSortableTableModel | null => {
  const match = tableId.match(/^pe-msvc-rtti-vftable-(\d+)-(bases|slots)$/);
  if (!match?.[1] || !match[2]) return null;
  const vftableIndex = Number(match[1]);
  const vftable = pe.msvcRtti?.vftables[vftableIndex];
  if (!vftable) return null;
  return match[2] === "bases"
    ? createBaseTableModel(pe, vftable, tableId)
    : createSlotTableModel(pe, vftable, tableId, symbolNames);
};
