"use strict";

import type {
  PeArm64RuntimeFunctionEntry,
  PeChpeCodeMapEntry,
  PeChpeEntryPointRange,
  PeChpeRedirection,
  PeEnclaveImport,
  PeHotPatchBase,
  PeLoadConfigReferences,
  PeVolatileMetadataRange
} from "../../analyzers/pe/load-config/reference-types.js";
import { hex } from "../../binary-utils.js";
import { escapeHtml } from "../../html-utils.js";
import type {
  PagedSortableTableCell,
  PagedSortableTableModel
} from "../paged-sortable-table.js";

// UI pagination size only; this never limits parsed or available entries.
const LOAD_CONFIG_REFERENCE_PAGE_SIZE = 250;

export const LOAD_CONFIG_REFERENCE_TABLE_IDS = {
  lockPrefixes: "pe-load-config-lock-prefixes",
  chpeCodeMap: "pe-load-config-chpe-code-map",
  chpeEntryPoints: "pe-load-config-chpe-entry-points",
  chpeRedirections: "pe-load-config-chpe-redirections",
  chpeRuntimeFunctions: "pe-load-config-chpe-runtime-functions",
  enclaveImports: "pe-load-config-enclave-imports",
  hotPatchBases: "pe-load-config-hot-patch-bases",
  volatileAccesses: "pe-load-config-volatile-accesses",
  volatileRanges: "pe-load-config-volatile-ranges"
} as const;

const textCell = (value: string): PagedSortableTableCell => ({
  html: escapeHtml(value),
  sortValue: value
});

const numberCell = (value: number): PagedSortableTableCell => ({
  className: "num",
  html: escapeHtml(String(value)),
  sortValue: String(value)
});

const hexCell = (value: number): PagedSortableTableCell => ({
  className: "num",
  html: escapeHtml(hex(value, 8)),
  sortValue: String(value)
});

const bytesText = (bytes: number[]): string => bytes.map(value => hex(value, 2)).join(" ");

const sortValue = (cells: PagedSortableTableCell[], columnIndex: number): string =>
  cells[columnIndex]?.sortValue ?? "";

const lockPrefixModel = (references: PeLoadConfigReferences): PagedSortableTableModel | null => {
  const entries = references.lockPrefixTable?.values;
  if (!entries?.length) return null;
  const rowCells = (index: number): PagedSortableTableCell[] => [
    numberCell(index), textCell(`0x${entries[index]?.toString(16) ?? "0"}`)
  ];
  return {
    id: LOAD_CONFIG_REFERENCE_TABLE_IDS.lockPrefixes,
    pageSize: LOAD_CONFIG_REFERENCE_PAGE_SIZE,
    rowCount: entries.length,
    columns: [{ className: "num", label: "#" }, { label: "Lock prefix VA" }],
    rowAt: index => entries[index] == null ? null : { cells: rowCells(index) },
    sortValueAt: (index, columnIndex) => entries[index] == null
      ? "" : sortValue(rowCells(index), columnIndex)
  };
};

const chpeCodeMapCells = (entry: PeChpeCodeMapEntry, index: number): PagedSortableTableCell[] => [
  numberCell(index), hexCell(entry.startRva), hexCell(entry.length), textCell(entry.kind)
];

const chpeCodeMapModel = (references: PeLoadConfigReferences): PagedSortableTableModel | null => {
  const entries = references.chpeMetadata?.codeMap;
  if (!entries?.length) return null;
  return {
    id: LOAD_CONFIG_REFERENCE_TABLE_IDS.chpeCodeMap,
    pageSize: LOAD_CONFIG_REFERENCE_PAGE_SIZE,
    rowCount: entries.length,
    columns: [
      { className: "num", label: "#" }, { className: "num", label: "Start RVA" },
      { className: "num", label: "Length" }, { label: "Kind" }
    ],
    rowAt: index => entries[index] ? { cells: chpeCodeMapCells(entries[index], index) } : null,
    sortValueAt: (index, columnIndex) => entries[index]
      ? sortValue(chpeCodeMapCells(entries[index], index), columnIndex) : ""
  };
};

const entryPointCells = (entry: PeChpeEntryPointRange, index: number): PagedSortableTableCell[] => [
  numberCell(index), hexCell(entry.startRva), hexCell(entry.endRva), hexCell(entry.entryPointRva)
];

const chpeEntryPointModel = (references: PeLoadConfigReferences): PagedSortableTableModel | null => {
  const metadata = references.chpeMetadata;
  const entries = metadata?.kind === "arm64ec" ? metadata.entryPointRanges : undefined;
  if (!entries?.length) return null;
  return {
    id: LOAD_CONFIG_REFERENCE_TABLE_IDS.chpeEntryPoints,
    pageSize: LOAD_CONFIG_REFERENCE_PAGE_SIZE,
    rowCount: entries.length,
    columns: [
      { className: "num", label: "#" }, { className: "num", label: "Start RVA" },
      { className: "num", label: "End RVA" }, { className: "num", label: "Entry point RVA" }
    ],
    rowAt: index => entries[index] ? { cells: entryPointCells(entries[index], index) } : null,
    sortValueAt: (index, columnIndex) => entries[index]
      ? sortValue(entryPointCells(entries[index], index), columnIndex) : ""
  };
};

const redirectionCells = (entry: PeChpeRedirection, index: number): PagedSortableTableCell[] => [
  numberCell(index), hexCell(entry.sourceRva), hexCell(entry.destinationRva)
];

const chpeRedirectionModel = (references: PeLoadConfigReferences): PagedSortableTableModel | null => {
  const metadata = references.chpeMetadata;
  const entries = metadata?.kind === "arm64ec" ? metadata.redirections : undefined;
  if (!entries?.length) return null;
  return {
    id: LOAD_CONFIG_REFERENCE_TABLE_IDS.chpeRedirections,
    pageSize: LOAD_CONFIG_REFERENCE_PAGE_SIZE,
    rowCount: entries.length,
    columns: [
      { className: "num", label: "#" }, { className: "num", label: "Source RVA" },
      { className: "num", label: "Destination RVA" }
    ],
    rowAt: index => entries[index] ? { cells: redirectionCells(entries[index], index) } : null,
    sortValueAt: (index, columnIndex) => entries[index]
      ? sortValue(redirectionCells(entries[index], index), columnIndex) : ""
  };
};

const runtimeFunctionCells = (
  entry: PeArm64RuntimeFunctionEntry,
  index: number
): PagedSortableTableCell[] => {
  const common = [numberCell(index), hexCell(entry.beginRva), textCell(entry.unwindKind)];
  if (entry.unwindKind === "exception") {
    return [...common, hexCell(entry.exceptionInformationRva), ...Array.from({ length: 6 }, () => textCell("-"))];
  }
  if (entry.unwindKind === "chained") {
    return [...common, hexCell(entry.targetPdataRva), ...Array.from({ length: 6 }, () => textCell("-"))];
  }
  return [
    ...common, textCell("-"), numberCell(entry.functionLengthBytes),
    numberCell(entry.savedFpRegisterField), numberCell(entry.savedIntegerRegisterCount),
    textCell(entry.homesIntegerParameters ? "yes" : "no"), textCell(entry.chainReturn),
    numberCell(entry.frameSizeBytes)
  ];
};

const runtimeFunctionModel = (references: PeLoadConfigReferences): PagedSortableTableModel | null => {
  const metadata = references.chpeMetadata;
  const entries = metadata?.kind === "arm64ec" ? metadata.extraRfeEntries : undefined;
  if (!entries?.length) return null;
  return {
    id: LOAD_CONFIG_REFERENCE_TABLE_IDS.chpeRuntimeFunctions,
    pageSize: LOAD_CONFIG_REFERENCE_PAGE_SIZE,
    rowCount: entries.length,
    columns: [
      { className: "num", label: "#" }, { className: "num", label: "Begin RVA" },
      { label: "Unwind kind" }, { className: "num", label: "Exception/reserved data" },
      { className: "num", label: "Function bytes" }, { className: "num", label: "RegF field" },
      { className: "num", label: "RegI count" }, { label: "Homes parameters" },
      { label: "Chain/return" }, { className: "num", label: "Frame bytes" }
    ],
    rowAt: index => entries[index] ? { cells: runtimeFunctionCells(entries[index], index) } : null,
    sortValueAt: (index, columnIndex) => entries[index]
      ? sortValue(runtimeFunctionCells(entries[index], index), columnIndex) : ""
  };
};

const enclaveImportCells = (entry: PeEnclaveImport, index: number): PagedSortableTableCell[] => [
  numberCell(index), textCell(entry.matchType), numberCell(entry.minimumSecurityVersion),
  textCell(entry.name ?? "-"), hexCell(entry.nameRva), textCell(bytesText(entry.uniqueOrAuthorId)),
  textCell(bytesText(entry.familyId)), textCell(bytesText(entry.imageId)), hexCell(entry.reserved)
];

const enclaveImportModel = (references: PeLoadConfigReferences): PagedSortableTableModel | null => {
  const entries = references.enclaveConfiguration?.imports;
  if (!entries?.length) return null;
  return {
    id: LOAD_CONFIG_REFERENCE_TABLE_IDS.enclaveImports,
    pageSize: LOAD_CONFIG_REFERENCE_PAGE_SIZE,
    rowCount: entries.length,
    columns: [
      { className: "num", label: "#" }, { label: "Match" },
      { className: "num", label: "Minimum SVN" }, { label: "Name" },
      { className: "num", label: "Name RVA" }, { label: "Unique/author ID" },
      { label: "Family ID" }, { label: "Image ID" }, { className: "num", label: "Reserved" }
    ],
    rowAt: index => entries[index] ? { cells: enclaveImportCells(entries[index], index) } : null,
    sortValueAt: (index, columnIndex) => entries[index]
      ? sortValue(enclaveImportCells(entries[index], index), columnIndex) : ""
  };
};

const hotPatchBaseCells = (entry: PeHotPatchBase, index: number): PagedSortableTableCell[] => [
  numberCell(index), numberCell(entry.sequenceNumber), hexCell(entry.flags),
  hexCell(entry.originalTimeDateStamp), hexCell(entry.originalCheckSum),
  hexCell(entry.codeIntegrityInfoOffset), numberCell(entry.codeIntegritySize),
  textCell(entry.codeIntegrityHashes ? bytesText(entry.codeIntegrityHashes.sha256) : "-"),
  textCell(entry.codeIntegrityHashes ? bytesText(entry.codeIntegrityHashes.sha1) : "-"),
  hexCell(entry.patchTableOffset),
  entry.bufferOffset == null ? textCell("-") : hexCell(entry.bufferOffset)
];

const hotPatchBaseModel = (references: PeLoadConfigReferences): PagedSortableTableModel | null => {
  const entries = references.hotPatch?.baseImages;
  if (!entries?.length) return null;
  return {
    id: LOAD_CONFIG_REFERENCE_TABLE_IDS.hotPatchBases,
    pageSize: LOAD_CONFIG_REFERENCE_PAGE_SIZE,
    rowCount: entries.length,
    columns: [
      { className: "num", label: "#" }, { className: "num", label: "Sequence" },
      { className: "num", label: "Flags" }, { className: "num", label: "Original timestamp" },
      { className: "num", label: "Original checksum" }, { className: "num", label: "CI info RVA" },
      { className: "num", label: "CI size" }, { label: "SHA-256" }, { label: "SHA-1" },
      { className: "num", label: "Patch table RVA" }, { className: "num", label: "Buffer offset" }
    ],
    rowAt: index => entries[index] ? { cells: hotPatchBaseCells(entries[index], index) } : null,
    sortValueAt: (index, columnIndex) => entries[index]
      ? sortValue(hotPatchBaseCells(entries[index], index), columnIndex) : ""
  };
};

const volatileAccessModel = (references: PeLoadConfigReferences): PagedSortableTableModel | null => {
  const entries = references.volatileMetadata?.accessRvas;
  if (!entries?.length) return null;
  const rowCells = (index: number): PagedSortableTableCell[] => [numberCell(index), hexCell(entries[index] ?? 0)];
  return {
    id: LOAD_CONFIG_REFERENCE_TABLE_IDS.volatileAccesses,
    pageSize: LOAD_CONFIG_REFERENCE_PAGE_SIZE,
    rowCount: entries.length,
    columns: [{ className: "num", label: "#" }, { className: "num", label: "RVA" }],
    rowAt: index => entries[index] == null ? null : { cells: rowCells(index) },
    sortValueAt: (index, columnIndex) => entries[index] == null
      ? "" : sortValue(rowCells(index), columnIndex)
  };
};

const volatileRangeCells = (entry: PeVolatileMetadataRange, index: number): PagedSortableTableCell[] => [
  numberCell(index), hexCell(entry.rva), hexCell(entry.size)
];

const volatileRangeModel = (references: PeLoadConfigReferences): PagedSortableTableModel | null => {
  const entries = references.volatileMetadata?.infoRanges;
  if (!entries?.length) return null;
  return {
    id: LOAD_CONFIG_REFERENCE_TABLE_IDS.volatileRanges,
    pageSize: LOAD_CONFIG_REFERENCE_PAGE_SIZE,
    rowCount: entries.length,
    columns: [
      { className: "num", label: "#" }, { className: "num", label: "Start RVA" },
      { className: "num", label: "Size" }
    ],
    rowAt: index => entries[index] ? { cells: volatileRangeCells(entries[index], index) } : null,
    sortValueAt: (index, columnIndex) => entries[index]
      ? sortValue(volatileRangeCells(entries[index], index), columnIndex) : ""
  };
};

export const getLoadConfigReferenceTableModel = (
  references: PeLoadConfigReferences,
  tableId: string
): PagedSortableTableModel | null => {
  if (tableId === LOAD_CONFIG_REFERENCE_TABLE_IDS.lockPrefixes) return lockPrefixModel(references);
  if (tableId === LOAD_CONFIG_REFERENCE_TABLE_IDS.chpeCodeMap) return chpeCodeMapModel(references);
  if (tableId === LOAD_CONFIG_REFERENCE_TABLE_IDS.chpeEntryPoints) return chpeEntryPointModel(references);
  if (tableId === LOAD_CONFIG_REFERENCE_TABLE_IDS.chpeRedirections) return chpeRedirectionModel(references);
  if (tableId === LOAD_CONFIG_REFERENCE_TABLE_IDS.chpeRuntimeFunctions) return runtimeFunctionModel(references);
  if (tableId === LOAD_CONFIG_REFERENCE_TABLE_IDS.enclaveImports) return enclaveImportModel(references);
  if (tableId === LOAD_CONFIG_REFERENCE_TABLE_IDS.hotPatchBases) return hotPatchBaseModel(references);
  if (tableId === LOAD_CONFIG_REFERENCE_TABLE_IDS.volatileAccesses) return volatileAccessModel(references);
  if (tableId === LOAD_CONFIG_REFERENCE_TABLE_IDS.volatileRanges) return volatileRangeModel(references);
  return null;
};
