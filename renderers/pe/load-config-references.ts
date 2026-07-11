"use strict";

import type {
  PeChpeMetadata,
  PeLoadConfigReferences
} from "../../analyzers/pe/load-config/reference-types.js";
import { hex } from "../../binary-utils.js";
import { escapeHtml } from "../../html-utils.js";
import { renderAutoPagedSortableTable } from "../paged-sortable-table.js";
import {
  getLoadConfigReferenceTableModel,
  LOAD_CONFIG_REFERENCE_TABLE_IDS
} from "./load-config-reference-tables.js";

type ReferenceRow = readonly [string, string];

const formatVa = (value: bigint, pointerWidth: number): string =>
  `0x${value.toString(16).padStart(pointerWidth, "0")}`;

const formatBytes = (bytes: number[]): string => bytes.map(value => hex(value, 2)).join(" ");

const renderRows = (rows: ReferenceRow[]): string =>
  `<dl>${rows.map(([name, value]) => `<dt>${escapeHtml(name)}</dt><dd>${escapeHtml(value)}</dd>`).join("")}</dl>`;

const renderReferenceTable = (
  references: PeLoadConfigReferences,
  tableId: string
): string => {
  const model = getLoadConfigReferenceTableModel(references, tableId);
  return model ? renderAutoPagedSortableTable(model) : "";
};

const renderPointerValues = (references: PeLoadConfigReferences, pointerWidth: number): string => {
  const rows: ReferenceRow[] = [
    ...(references.securityCookie ? [[
      "SecurityCookie value",
      formatVa(references.securityCookie.value, pointerWidth)
    ] as const] : []),
    ...Object.entries(references.pointerSlots ?? {}).flatMap(([name, value]) => value ? [[
      `${name} value`,
      formatVa(value.value, pointerWidth)
    ] as const] : [])
  ];
  return rows.length ? `<h4>Pointer values</h4>${renderRows(rows)}` : "";
};

const renderLockPrefixTable = (references: PeLoadConfigReferences): string => {
  const table = references.lockPrefixTable;
  if (!table) return "";
  const state = table.terminated ? "terminated" : "unterminated";
  return `<h4>LockPrefixTable (${table.values.length}, ${state})</h4>` +
    renderReferenceTable(references, LOAD_CONFIG_REFERENCE_TABLE_IDS.lockPrefixes);
};

const arm64EcRows = (metadata: Extract<PeChpeMetadata, { kind: "arm64ec" }>): ReferenceRow[] => [
  ["Code ranges to entry points RVA", hex(metadata.codeRangesToEntryPointsRva, 8)],
  ["Code ranges to entry points count", String(metadata.codeRangesToEntryPointsCount)],
  ["Redirection metadata RVA", hex(metadata.redirectionMetadataRva, 8)],
  ["Redirection metadata count", String(metadata.redirectionMetadataCount)],
  ["Dispatch call no-redirect RVA", hex(metadata.osArm64xDispatchCallNoRedirectRva, 8)],
  ["Dispatch return RVA", hex(metadata.osArm64xDispatchRetRva, 8)],
  ["Dispatch call RVA", hex(metadata.osArm64xDispatchCallRva, 8)],
  ["Dispatch indirect-call RVA", hex(metadata.osArm64xDispatchIcallRva, 8)],
  ["Dispatch CFG indirect-call RVA", hex(metadata.osArm64xDispatchIcallCfgRva, 8)],
  ["Alternate entry point RVA", hex(metadata.alternateEntryPointRva, 8)],
  ["Auxiliary IAT RVA", hex(metadata.auxiliaryIatRva, 8)],
  ["Get x64 information RVA", hex(metadata.getX64InformationFunctionPointerRva, 8)],
  ["Set x64 information RVA", hex(metadata.setX64InformationFunctionPointerRva, 8)],
  ["Extra RFE table RVA", hex(metadata.extraRfeTableRva, 8)],
  ["Extra RFE table size", hex(metadata.extraRfeTableSize, 8)],
  ["Dispatch function-pointer RVA", hex(metadata.osArm64xDispatchFptrRva, 8)],
  ["Auxiliary IAT copy RVA", hex(metadata.auxiliaryIatCopyRva, 8)],
  ...(metadata.auxiliaryDelayloadIatRva == null ? [] : [[
    "Auxiliary delay-load IAT RVA", hex(metadata.auxiliaryDelayloadIatRva, 8)
  ] as const]),
  ...(metadata.auxiliaryDelayloadIatCopyRva == null ? [] : [[
    "Auxiliary delay-load IAT copy RVA", hex(metadata.auxiliaryDelayloadIatCopyRva, 8)
  ] as const]),
  ...(metadata.hybridImageInfoBitfield == null ? [] : [[
    "Hybrid image info bitfield", hex(metadata.hybridImageInfoBitfield, 8)
  ] as const])
];

const x86Rows = (metadata: Extract<PeChpeMetadata, { kind: "x86" }>): ReferenceRow[] => [
  ["WowA64 exception handler RVA", hex(metadata.wowA64ExceptionHandlerRva, 8)],
  ["WowA64 dispatch call RVA", hex(metadata.wowA64DispatchCallRva, 8)],
  ["WowA64 dispatch indirect-call RVA", hex(metadata.wowA64DispatchIndirectCallRva, 8)],
  ["WowA64 dispatch CFG indirect-call RVA", hex(metadata.wowA64DispatchIndirectCallCfgRva, 8)],
  ["WowA64 dispatch return RVA", hex(metadata.wowA64DispatchRetRva, 8)],
  ["WowA64 dispatch leaf-return RVA", hex(metadata.wowA64DispatchRetLeafRva, 8)],
  ["WowA64 dispatch jump RVA", hex(metadata.wowA64DispatchJumpRva, 8)],
  ...(metadata.compilerIatRva == null ? [] : [["Compiler IAT RVA", hex(metadata.compilerIatRva, 8)] as const]),
  ...(metadata.wowA64RdtscRva == null ? [] : [["WowA64 RDTSC RVA", hex(metadata.wowA64RdtscRva, 8)] as const])
];

const renderChpeMetadata = (references: PeLoadConfigReferences): string => {
  const metadata = references.chpeMetadata;
  if (!metadata) return "";
  const rows: ReferenceRow[] = [
    ["Kind", metadata.kind], ["Version", String(metadata.version)], ["RVA", hex(metadata.rva, 8)],
    ["Code map RVA", hex(metadata.codeMapRva, 8)], ["Code map count", String(metadata.codeMapCount)],
    ...(metadata.kind === "arm64ec" ? arm64EcRows(metadata) : x86Rows(metadata))
  ];
  const codeMap = renderReferenceTable(references, LOAD_CONFIG_REFERENCE_TABLE_IDS.chpeCodeMap);
  const entryPoints = renderReferenceTable(references, LOAD_CONFIG_REFERENCE_TABLE_IDS.chpeEntryPoints);
  const redirections = renderReferenceTable(references, LOAD_CONFIG_REFERENCE_TABLE_IDS.chpeRedirections);
  const runtimeFunctions = renderReferenceTable(
    references, LOAD_CONFIG_REFERENCE_TABLE_IDS.chpeRuntimeFunctions
  );
  return `<h4>CHPE metadata</h4>${renderRows(rows)}` +
    `${codeMap ? `<h5>Code map</h5>${codeMap}` : ""}` +
    `${entryPoints ? `<h5>Code ranges to entry points</h5>${entryPoints}` : ""}` +
    `${redirections ? `<h5>Redirections</h5>${redirections}` : ""}` +
    `${runtimeFunctions ? `<h5>Extra ARM64 runtime functions</h5>${runtimeFunctions}` : ""}`;
};

const renderEnclaveConfiguration = (references: PeLoadConfigReferences, pointerWidth: number): string => {
  const config = references.enclaveConfiguration;
  if (!config) return "";
  const rows: ReferenceRow[] = [
    ["RVA", hex(config.rva, 8)], ["Size", hex(config.size, 8)],
    ["MinimumRequiredConfigSize", hex(config.minimumRequiredConfigSize, 8)],
    ["PolicyFlags", hex(config.policyFlags, 8)], ["NumberOfImports", String(config.numberOfImports)],
    ["ImportList RVA", hex(config.importListRva, 8)], ["ImportEntrySize", String(config.importEntrySize)],
    ["FamilyID", formatBytes(config.familyId)], ["ImageID", formatBytes(config.imageId)],
    ["ImageVersion", hex(config.imageVersion, 8)], ["SecurityVersion", hex(config.securityVersion, 8)],
    ["EnclaveSize", formatVa(config.enclaveSize, pointerWidth)],
    ["NumberOfThreads", String(config.numberOfThreads)],
    ...(config.enclaveFlags == null ? [] : [["EnclaveFlags", hex(config.enclaveFlags, 8)] as const])
  ];
  const imports = renderReferenceTable(references, LOAD_CONFIG_REFERENCE_TABLE_IDS.enclaveImports);
  return `<h4>Enclave configuration</h4>${renderRows(rows)}` +
    `${imports ? `<h5>Imports</h5>${imports}` : ""}`;
};

const renderHotPatch = (references: PeLoadConfigReferences): string => {
  const info = references.hotPatch;
  if (!info) return "";
  const rows: ReferenceRow[] = [
    ["RVA", hex(info.rva, 8)], ["Version", String(info.version)], ["Size", hex(info.size, 8)],
    ["SequenceNumber", String(info.sequenceNumber)],
    ["BaseImageList offset", hex(info.baseImageListOffset, 8)],
    ["BaseImageCount", String(info.baseImageCount)],
    ...(info.bufferOffset == null ? [] : [["BufferOffset", hex(info.bufferOffset, 8)] as const]),
    ...(info.extraPatchSize == null ? [] : [["ExtraPatchSize", hex(info.extraPatchSize, 8)] as const]),
    ...(info.minSequenceNumber == null ? [] : [["MinSequenceNumber", String(info.minSequenceNumber)] as const]),
    ...(info.flags == null ? [] : [["Flags", hex(info.flags, 8)] as const])
  ];
  const bases = renderReferenceTable(references, LOAD_CONFIG_REFERENCE_TABLE_IDS.hotPatchBases);
  return `<h4>Hot patch information</h4>${renderRows(rows)}` +
    `${bases ? `<h5>Base images</h5>${bases}` : ""}`;
};

const renderVolatileMetadata = (references: PeLoadConfigReferences): string => {
  const metadata = references.volatileMetadata;
  if (!metadata) return "";
  const rows: ReferenceRow[] = [
    ["RVA", hex(metadata.rva, 8)], ["Size", hex(metadata.size, 8)],
    ["Minimum version", String(metadata.minimumVersion)], ["Maximum version", String(metadata.maximumVersion)],
    ["Access table RVA", hex(metadata.accessTableRva, 8)], ["Access table size", String(metadata.accessTableSize)],
    ["Info range table RVA", hex(metadata.infoRangeTableRva, 8)],
    ["Info range table size", String(metadata.infoRangeTableSize)]
  ];
  const accesses = renderReferenceTable(references, LOAD_CONFIG_REFERENCE_TABLE_IDS.volatileAccesses);
  const ranges = renderReferenceTable(references, LOAD_CONFIG_REFERENCE_TABLE_IDS.volatileRanges);
  return `<h4>Volatile metadata</h4>${renderRows(rows)}` +
    `${accesses ? `<h5>Volatile access RVAs</h5>${accesses}` : ""}` +
    `${ranges ? `<h5>Volatile info ranges</h5>${ranges}` : ""}`;
};

const renderOpaqueReferences = (references: PeLoadConfigReferences, pointerWidth: number): string => {
  if (!references.opaque?.length) return "";
  const rows = references.opaque.map(reference => `<li><b>${reference.name}</b> ` +
    `${formatVa(reference.pointerVa, pointerWidth)} — ${escapeHtml(reference.reason)}</li>`);
  return `<h4>Documented opaque references</h4><ul>${rows.join("")}</ul>`;
};

export const renderLoadConfigReferences = (
  references: PeLoadConfigReferences,
  pointerWidth: number
): string => {
  const body = renderPointerValues(references, pointerWidth) + renderLockPrefixTable(references) +
    renderChpeMetadata(references) + renderEnclaveConfiguration(references, pointerWidth) +
    renderHotPatch(references) + renderVolatileMetadata(references) +
    renderOpaqueReferences(references, pointerWidth);
  if (!body) return "";
  return `<details class="loadConfigReferences"><summary class="loadConfigNestedSummary">` +
    `<b>Referenced Load Config data</b></summary>${body}</details>`;
};
