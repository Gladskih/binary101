"use strict";

import { hex, humanSize, isoOrDash } from "../../binary-utils.js";
import { renderDefinitionRow, escapeHtml } from "../../html-utils.js";
import {
  PE32_PLUS_OPTIONAL_HEADER_MAGIC
} from "../../analyzers/pe/optional-header/magic.js";
import type { PeWindowsParseResult } from "../../analyzers/pe/index.js";
import { renderPeSectionEnd, renderPeSectionStart } from "./collapsible-section.js";
import {
  renderLoadConfigAddressTables,
  renderLoadConfigChecks,
  renderLoadConfigDynamicRelocations,
  renderLoadConfigGuardFlags
} from "./load-config-widgets.js";
import { renderLoadConfigReferences } from "./load-config-references.js";
import { formatBigByteSize } from "./header-format.js";
const formatPointerHex = (value: bigint, width: number): string =>
  `0x${value.toString(16).padStart(width, "0")}`;

const valueWithNote = (valueHtml: string, note: string): string =>
  `${valueHtml}<div class="smallNote" style="margin:0">${escapeHtml(note)}</div>`;

type RenderField = (label: string, valueHtml: string, meaning: string) => string;
const renderAvailableField = (unavailable: Set<string>): RenderField =>
  (label, valueHtml, meaning) => {
    const isUnavailable = label === "Version"
      ? unavailable.has("Major") || unavailable.has("Minor")
      : unavailable.has(label);
    return renderDefinitionRow(label,
      valueWithNote(isUnavailable ? "Unavailable" : valueHtml, meaning), meaning);
  };

const hasLoadConfigTableInfo = (table: { entries: unknown[]; notes?: string[]; warnings?: string[] }): boolean =>
  table.entries.length > 0 || Boolean(table.notes?.length || table.warnings?.length);

type LoadConfigFields = PeWindowsParseResult["loadcfg"];
type FormatVa = (value: bigint) => string;

const renderLoadConfigCoreFields = (
  lc: NonNullable<LoadConfigFields>, formatVa: FormatVa, renderField: RenderField, out: string[]
): void => {
  out.push(renderField("Size", humanSize(lc.Size),
    "Structure size of IMAGE_LOAD_CONFIG_DIRECTORY."));
  out.push(renderField("TimeDateStamp", isoOrDash(lc.TimeDateStamp),
    "Build timestamp for load config data."));
  out.push(renderField("Version", `${lc.Major}.${lc.Minor}`,
    "Load config version (varies between OS/toolchain versions)."));
  out.push(renderField("GlobalFlagsClear", hex(lc.GlobalFlagsClear, 8),
    "Global loader flags to clear for the process."));
  out.push(renderField("GlobalFlagsSet", hex(lc.GlobalFlagsSet, 8),
    "Global loader flags to set for the process."));
  out.push(renderField("CriticalSectionDefaultTimeout", hex(lc.CriticalSectionDefaultTimeout, 8),
    "Default critical section timeout used by the runtime/loader."));
  out.push(renderField("DeCommitFreeBlockThreshold", formatBigByteSize(lc.DeCommitFreeBlockThreshold),
    "Heap free-block threshold for decommit (legacy)."));
  out.push(renderField("DeCommitTotalFreeThreshold", formatBigByteSize(lc.DeCommitTotalFreeThreshold),
    "Heap total-free threshold for decommit (legacy)."));
  out.push(renderField("LockPrefixTable", formatVa(lc.LockPrefixTable),
    "Pointer to the lock prefix table (legacy)."));
  out.push(renderField("MaximumAllocationSize", formatBigByteSize(lc.MaximumAllocationSize),
    "Maximum allocation size used by the heap/loader (legacy)."));
  out.push(renderField("VirtualMemoryThreshold", formatBigByteSize(lc.VirtualMemoryThreshold),
    "Virtual memory threshold used by the heap/loader (legacy)."));
  out.push(renderField("ProcessHeapFlags", hex(lc.ProcessHeapFlags, 8),
    "Flags used when creating the default process heap."));
  out.push(renderField("ProcessAffinityMask", `0x${lc.ProcessAffinityMask.toString(16)}`,
    "Preferred processor affinity mask (legacy)."));
  out.push(renderField("CSDVersion", hex(lc.CSDVersion, 4),
    "CSD (Service Pack) version field (legacy)."));
  out.push(renderField("DependentLoadFlags", hex(lc.DependentLoadFlags, 4),
    "Flags affecting how dependent DLLs are loaded."));
  out.push(renderField("EditList", formatVa(lc.EditList),
    "Pointer to an edit list (hotpatch/legacy)."));
  out.push(renderField("SecurityCookie", formatVa(lc.SecurityCookie),
    "Address of the GS cookie (stack guard)."));
  out.push(renderField("SEHandlerTable", formatVa(lc.SEHandlerTable),
    "SafeSEH handler table (x86 only)."));
  out.push(renderField("SEHandlerCount", String(lc.SEHandlerCount ?? "-"),
    "Number of SafeSEH handlers (x86)."));
};

const renderLoadConfigGuardFields = (
  lc: NonNullable<LoadConfigFields>, formatVa: FormatVa, renderField: RenderField, out: string[]
): void => {
  out.push(renderField("GuardCFCheckFunctionPointer", formatVa(lc.GuardCFCheckFunctionPointer),
    "CFG: guard check function pointer used to validate indirect call/jump targets."));
  out.push(renderField("GuardCFDispatchFunctionPointer", formatVa(lc.GuardCFDispatchFunctionPointer),
    "CFG: guard dispatch function pointer used for certain indirect control transfers."));
  out.push(renderField("GuardCFFunctionTable", formatVa(lc.GuardCFFunctionTable),
    "CFG function table VA."));
  out.push(renderField("GuardCFFunctionCount", String(lc.GuardCFFunctionCount ?? "-"),
    "Number of CFG functions listed."));
  out.push(renderField("CodeIntegrity.Flags", hex(lc.CodeIntegrity.Flags, 4),
    "IMAGE_LOAD_CONFIG_CODE_INTEGRITY flags."));
  out.push(renderField("CodeIntegrity.Catalog", hex(lc.CodeIntegrity.Catalog, 4),
    "Catalog identifier used by code integrity."));
  out.push(renderField("CodeIntegrity.CatalogOffset", hex(lc.CodeIntegrity.CatalogOffset, 8),
    "Catalog offset used by code integrity."));
  out.push(renderField("CodeIntegrity.Reserved", hex(lc.CodeIntegrity.Reserved, 8),
    "Reserved (code integrity)."));
  out.push(renderField("VolatileMetadataPointer", formatVa(lc.VolatileMetadataPointer),
    "Pointer to optional 'volatile metadata' referenced from the load config (format is not documented in Win32 API docs)."));
  out.push(renderField("GuardEHContinuationTable", formatVa(lc.GuardEHContinuationTable),
    "CFG: VA of EH continuation table (valid exception-handling continuation targets)."));
  out.push(renderField("GuardEHContinuationCount", String(lc.GuardEHContinuationCount ?? "-"),
    "Number of EH continuation targets in the table."));
  out.push(renderField("GuardLongJumpTargetTable", formatVa(lc.GuardLongJumpTargetTable),
    "CFG: VA of longjmp target table (valid longjmp destinations)."));
  out.push(renderField("GuardLongJumpTargetCount", String(lc.GuardLongJumpTargetCount ?? "-"),
    "Number of longjmp targets in the table."));
  out.push(renderField("GuardAddressTakenIatEntryTable", formatVa(lc.GuardAddressTakenIatEntryTable),
    "CFG: VA of the address-taken IAT entry table (IAT slots whose imported addresses may be used as function-pointer values, so they remain valid indirect-call targets)."));
  out.push(renderField("GuardAddressTakenIatEntryCount", String(lc.GuardAddressTakenIatEntryCount ?? "-"),
    "Number of entries in GuardAddressTakenIatEntryTable."));
};

const renderLoadConfigExtendedFields = (
  lc: NonNullable<LoadConfigFields>, formatVa: FormatVa, renderField: RenderField, out: string[]
): void => {
  out.push(renderField("DynamicValueRelocTable", formatVa(lc.DynamicValueRelocTable),
    "Pointer to the dynamic relocations table (if used)."));
  out.push(renderField("CHPEMetadataPointer", formatVa(lc.CHPEMetadataPointer),
    "Pointer to CHPE metadata (used by ARM64EC/CHPE images)."));
  out.push(renderField("GuardRFFailureRoutine", formatVa(lc.GuardRFFailureRoutine),
    "GuardRF failure routine pointer (if present)."));
  out.push(renderField("GuardRFFailureRoutineFunctionPointer", formatVa(lc.GuardRFFailureRoutineFunctionPointer),
    "Pointer to GuardRF failure routine function pointer."));
  out.push(renderField("DynamicValueRelocTableOffset", hex(lc.DynamicValueRelocTableOffset, 8),
    "Offset of the dynamic relocations table within DynamicValueRelocTableSection."));
  out.push(renderField("DynamicValueRelocTableSection", hex(lc.DynamicValueRelocTableSection, 4),
    "Section index for DynamicValueRelocTableOffset (1-based)."));
  out.push(renderField("Reserved2", hex(lc.Reserved2, 4), "Reserved."));
  out.push(renderField("GuardRFVerifyStackPointerFunctionPointer", formatVa(lc.GuardRFVerifyStackPointerFunctionPointer),
    "GuardRF verify stack pointer function pointer."));
  out.push(renderField("HotPatchTableOffset", hex(lc.HotPatchTableOffset, 8),
    "Offset of hotpatch data (if present)."));
  out.push(renderField("Reserved3", hex(lc.Reserved3, 8), "Reserved."));
  out.push(renderField("EnclaveConfigurationPointer", formatVa(lc.EnclaveConfigurationPointer),
    "Pointer to enclave configuration (if present)."));
  out.push(renderField("GuardXFGCheckFunctionPointer", formatVa(lc.GuardXFGCheckFunctionPointer),
    "XFG: extended-flow-guard check function pointer."));
  out.push(renderField("GuardXFGDispatchFunctionPointer", formatVa(lc.GuardXFGDispatchFunctionPointer),
    "XFG: extended-flow-guard dispatch function pointer."));
  out.push(renderField("GuardXFGTableDispatchFunctionPointer", formatVa(lc.GuardXFGTableDispatchFunctionPointer),
    "XFG: table dispatch function pointer."));
  out.push(renderField("CastGuardOsDeterminedFailureMode", formatVa(lc.CastGuardOsDeterminedFailureMode),
    "CASTGuard OS-determined failure mode value/pointer (undocumented)."));
  out.push(renderField("GuardMemcpyFunctionPointer", formatVa(lc.GuardMemcpyFunctionPointer),
    "CFG: guard memcpy function pointer used by some toolchains/runtime checks."));
  out.push(renderField("UmaFunctionPointers", formatVa(lc.UmaFunctionPointers),
    "Pointer to UMA function pointers (undocumented)."));
  out.push(renderField("GuardFlags", renderLoadConfigGuardFlags(lc),
    "Control Flow Guard related flags."));
};

const renderLoadConfigTables = (
  pe: PeWindowsParseResult, lc: NonNullable<LoadConfigFields>, pointerWidth: number, out: string[]
): void => {
  out.push(renderLoadConfigAddressTables([
    ...(lc.tables?.safeSehHandler && hasLoadConfigTableInfo(lc.tables.safeSehHandler)
      ? [[lc.tables.safeSehHandler, "SafeSEH handlers (x86 only)."] as const]
      : []),
    ...(lc.tables?.guardFid && hasLoadConfigTableInfo(lc.tables.guardFid)
      ? [[
          lc.tables.guardFid,
          "CFG function targets (GFIDS), including optional GFIDS metadata flags."
        ] as const]
      : []),
    ...(lc.tables?.guardIat && hasLoadConfigTableInfo(lc.tables.guardIat)
      ? [[
          lc.tables.guardIat,
          "Address-taken IAT entries (IAT slots whose imported addresses may be used as function pointers under CFG)."
        ] as const]
      : []),
    ...(lc.tables?.guardLongJumpTarget && hasLoadConfigTableInfo(lc.tables.guardLongJumpTarget)
      ? [[lc.tables.guardLongJumpTarget, "Valid longjmp destinations under CFG."] as const]
      : []),
    ...(lc.tables?.guardEhContinuation && hasLoadConfigTableInfo(lc.tables.guardEhContinuation)
      ? [[lc.tables.guardEhContinuation, "Valid exception continuation targets under CFG."] as const]
      : [])
  ], pe.sections, pe.opt.ImageBase, pointerWidth));
};

export function renderLoadConfig(pe: PeWindowsParseResult, out: string[]): void {
  if (!pe.loadcfg) return;
  const lc = pe.loadcfg;
  const pointerWidth = pe.opt.Magic === PE32_PLUS_OPTIONAL_HEADER_MAGIC ? 16 : 8;
  const formatVa = (value: bigint): string =>
    value === 0n ? "-" : formatPointerHex(value, pointerWidth);

  const unavailable = new Set(lc.unavailableFields);
  const version = unavailable.has("Major") || unavailable.has("Minor") || unavailable.has("Size")
    ? undefined : `v${lc.Major}.${lc.Minor}`;
  out.push(renderPeSectionStart("Load Config", version));
  if (lc.warnings?.length) {
    out.push(`<div class="smallNote" style="color:var(--warn-fg)">${escapeHtml(lc.warnings.join("; "))}</div>`);
  }
  if (lc.notes?.length) {
    out.push(`<div class="smallNote">${escapeHtml(lc.notes.join("; "))}</div>`);
  }
  if (unavailable.has("Size")) {
    out.push(renderPeSectionEnd());
    return;
  }
  const renderField = renderAvailableField(unavailable);
  out.push(`<dl>`);
  renderLoadConfigCoreFields(lc, formatVa, renderField, out);
  renderLoadConfigGuardFields(lc, formatVa, renderField, out);
  renderLoadConfigExtendedFields(lc, formatVa, renderField, out);
  out.push(`</dl>`);
  out.push(renderLoadConfigChecks(lc));

  if (lc.dynamicRelocations) {
    out.push(renderLoadConfigDynamicRelocations(lc.dynamicRelocations, pe.imports));
  }
  if (lc.references) out.push(renderLoadConfigReferences(lc.references, pointerWidth));
  renderLoadConfigTables(pe, lc, pointerWidth, out);
  out.push(renderPeSectionEnd());
}
