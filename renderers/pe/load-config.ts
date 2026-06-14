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
const formatPointerHex = (value: bigint, width: number): string =>
  `0x${value.toString(16).padStart(width, "0")}`;

const valueWithNote = (valueHtml: string, note: string): string =>
  `${valueHtml}<div class="smallNote" style="margin:0">${escapeHtml(note)}</div>`;

const renderLoadConfigDefinitionRow = (label: string, valueHtml: string, tooltip?: string | null): string =>
  renderDefinitionRow(label, tooltip ? valueWithNote(valueHtml, tooltip) : valueHtml, tooltip);

const hasLoadConfigTableInfo = (table: { entries: unknown[]; notes?: string[]; warnings?: string[] }): boolean =>
  table.entries.length > 0 || Boolean(table.notes?.length || table.warnings?.length);

type LoadConfigFields = PeWindowsParseResult["loadcfg"];
type FormatVa = (value: bigint) => string;

const renderLoadConfigCoreFields = (lc: NonNullable<LoadConfigFields>, formatVa: FormatVa, out: string[]): void => {
  out.push(renderLoadConfigDefinitionRow("Size", humanSize(lc.Size), "Structure size of IMAGE_LOAD_CONFIG_DIRECTORY."));
  out.push(renderLoadConfigDefinitionRow("TimeDateStamp", isoOrDash(lc.TimeDateStamp), "Build timestamp for load config data."));
  out.push(renderLoadConfigDefinitionRow("Version", `${lc.Major}.${lc.Minor}`, "Load config version (varies between OS/toolchain versions)."));
  out.push(renderLoadConfigDefinitionRow("GlobalFlagsClear", hex(lc.GlobalFlagsClear, 8), "Global loader flags to clear for the process."));
  out.push(renderLoadConfigDefinitionRow("GlobalFlagsSet", hex(lc.GlobalFlagsSet, 8), "Global loader flags to set for the process."));
  out.push(renderLoadConfigDefinitionRow("CriticalSectionDefaultTimeout", hex(lc.CriticalSectionDefaultTimeout, 8), "Default critical section timeout used by the runtime/loader."));
  out.push(renderLoadConfigDefinitionRow("DeCommitFreeBlockThreshold", formatVa(lc.DeCommitFreeBlockThreshold), "Heap free-block threshold for decommit (legacy)."));
  out.push(renderLoadConfigDefinitionRow("DeCommitTotalFreeThreshold", formatVa(lc.DeCommitTotalFreeThreshold), "Heap total-free threshold for decommit (legacy)."));
  out.push(renderLoadConfigDefinitionRow("LockPrefixTable", formatVa(lc.LockPrefixTable), "Pointer to the lock prefix table (legacy)."));
  out.push(renderLoadConfigDefinitionRow("MaximumAllocationSize", formatVa(lc.MaximumAllocationSize), "Maximum allocation size used by the heap/loader (legacy)."));
  out.push(renderLoadConfigDefinitionRow("VirtualMemoryThreshold", formatVa(lc.VirtualMemoryThreshold), "Virtual memory threshold used by the heap/loader (legacy)."));
  out.push(renderLoadConfigDefinitionRow("ProcessHeapFlags", hex(lc.ProcessHeapFlags, 8), "Flags used when creating the default process heap."));
  out.push(renderLoadConfigDefinitionRow("ProcessAffinityMask", formatVa(lc.ProcessAffinityMask), "Preferred processor affinity mask (legacy)."));
  out.push(renderLoadConfigDefinitionRow("CSDVersion", hex(lc.CSDVersion, 4), "CSD (Service Pack) version field (legacy)."));
  out.push(renderLoadConfigDefinitionRow("DependentLoadFlags", hex(lc.DependentLoadFlags, 4), "Flags affecting how dependent DLLs are loaded."));
  out.push(renderLoadConfigDefinitionRow("EditList", formatVa(lc.EditList), "Pointer to an edit list (hotpatch/legacy)."));
  out.push(renderLoadConfigDefinitionRow("SecurityCookie", formatVa(lc.SecurityCookie), "Address of the GS cookie (stack guard)."));
  out.push(renderLoadConfigDefinitionRow("SEHandlerTable", formatVa(lc.SEHandlerTable), "SafeSEH handler table (x86 only)."));
  out.push(renderLoadConfigDefinitionRow("SEHandlerCount", String(lc.SEHandlerCount ?? "-"), "Number of SafeSEH handlers (x86)."));
};

const renderLoadConfigGuardFields = (lc: NonNullable<LoadConfigFields>, formatVa: FormatVa, out: string[]): void => {
  out.push(renderLoadConfigDefinitionRow("GuardCFCheckFunctionPointer", formatVa(lc.GuardCFCheckFunctionPointer), "CFG: guard check function pointer used to validate indirect call/jump targets."));
  out.push(renderLoadConfigDefinitionRow("GuardCFDispatchFunctionPointer", formatVa(lc.GuardCFDispatchFunctionPointer), "CFG: guard dispatch function pointer used for certain indirect control transfers."));
  out.push(renderLoadConfigDefinitionRow("GuardCFFunctionTable", formatVa(lc.GuardCFFunctionTable), "CFG function table VA."));
  out.push(renderLoadConfigDefinitionRow("GuardCFFunctionCount", String(lc.GuardCFFunctionCount ?? "-"), "Number of CFG functions listed."));
  out.push(renderLoadConfigDefinitionRow("CodeIntegrity.Flags", hex(lc.CodeIntegrity.Flags, 4), "IMAGE_LOAD_CONFIG_CODE_INTEGRITY flags."));
  out.push(renderLoadConfigDefinitionRow("CodeIntegrity.Catalog", hex(lc.CodeIntegrity.Catalog, 4), "Catalog identifier used by code integrity."));
  out.push(renderLoadConfigDefinitionRow("CodeIntegrity.CatalogOffset", hex(lc.CodeIntegrity.CatalogOffset, 8), "Catalog offset used by code integrity."));
  out.push(renderLoadConfigDefinitionRow("CodeIntegrity.Reserved", hex(lc.CodeIntegrity.Reserved, 8), "Reserved (code integrity)."));
  out.push(renderLoadConfigDefinitionRow("VolatileMetadataPointer", formatVa(lc.VolatileMetadataPointer), "Pointer to optional 'volatile metadata' referenced from the load config (format is not documented in Win32 API docs)."));
  out.push(renderLoadConfigDefinitionRow("GuardEHContinuationTable", formatVa(lc.GuardEHContinuationTable), "CFG: VA of EH continuation table (valid exception-handling continuation targets)."));
  out.push(renderLoadConfigDefinitionRow("GuardEHContinuationCount", String(lc.GuardEHContinuationCount ?? "-"), "Number of EH continuation targets in the table."));
  out.push(renderLoadConfigDefinitionRow("GuardLongJumpTargetTable", formatVa(lc.GuardLongJumpTargetTable), "CFG: VA of longjmp target table (valid longjmp destinations)."));
  out.push(renderLoadConfigDefinitionRow("GuardLongJumpTargetCount", String(lc.GuardLongJumpTargetCount ?? "-"), "Number of longjmp targets in the table."));
  out.push(renderLoadConfigDefinitionRow("GuardAddressTakenIatEntryTable", formatVa(lc.GuardAddressTakenIatEntryTable), "CFG: VA of the address-taken IAT entry table (IAT slots whose imported addresses may be used as function-pointer values, so they remain valid indirect-call targets)."));
  out.push(renderLoadConfigDefinitionRow("GuardAddressTakenIatEntryCount", String(lc.GuardAddressTakenIatEntryCount ?? "-"), "Number of entries in GuardAddressTakenIatEntryTable."));
};

const renderLoadConfigExtendedFields = (lc: NonNullable<LoadConfigFields>, formatVa: FormatVa, out: string[]): void => {
  out.push(renderLoadConfigDefinitionRow("DynamicValueRelocTable", formatVa(lc.DynamicValueRelocTable), "Pointer to the dynamic relocations table (if used)."));
  out.push(renderLoadConfigDefinitionRow("CHPEMetadataPointer", formatVa(lc.CHPEMetadataPointer), "Pointer to CHPE metadata (used by ARM64EC/CHPE images)."));
  out.push(renderLoadConfigDefinitionRow("GuardRFFailureRoutine", formatVa(lc.GuardRFFailureRoutine), "GuardRF failure routine pointer (if present)."));
  out.push(renderLoadConfigDefinitionRow("GuardRFFailureRoutineFunctionPointer", formatVa(lc.GuardRFFailureRoutineFunctionPointer), "Pointer to GuardRF failure routine function pointer."));
  out.push(renderLoadConfigDefinitionRow("DynamicValueRelocTableOffset", hex(lc.DynamicValueRelocTableOffset, 8), "Offset of the dynamic relocations table within DynamicValueRelocTableSection."));
  out.push(renderLoadConfigDefinitionRow("DynamicValueRelocTableSection", hex(lc.DynamicValueRelocTableSection, 4), "Section index for DynamicValueRelocTableOffset (1-based)."));
  out.push(renderLoadConfigDefinitionRow("Reserved2", hex(lc.Reserved2, 4), "Reserved."));
  out.push(renderLoadConfigDefinitionRow("GuardRFVerifyStackPointerFunctionPointer", formatVa(lc.GuardRFVerifyStackPointerFunctionPointer), "GuardRF verify stack pointer function pointer."));
  out.push(renderLoadConfigDefinitionRow("HotPatchTableOffset", hex(lc.HotPatchTableOffset, 8), "Offset of hotpatch data (if present)."));
  out.push(renderLoadConfigDefinitionRow("Reserved3", hex(lc.Reserved3, 8), "Reserved."));
  out.push(renderLoadConfigDefinitionRow("EnclaveConfigurationPointer", formatVa(lc.EnclaveConfigurationPointer), "Pointer to enclave configuration (if present)."));
  out.push(renderLoadConfigDefinitionRow("GuardXFGCheckFunctionPointer", formatVa(lc.GuardXFGCheckFunctionPointer), "XFG: extended-flow-guard check function pointer."));
  out.push(renderLoadConfigDefinitionRow("GuardXFGDispatchFunctionPointer", formatVa(lc.GuardXFGDispatchFunctionPointer), "XFG: extended-flow-guard dispatch function pointer."));
  out.push(renderLoadConfigDefinitionRow("GuardXFGTableDispatchFunctionPointer", formatVa(lc.GuardXFGTableDispatchFunctionPointer), "XFG: table dispatch function pointer."));
  out.push(renderLoadConfigDefinitionRow("CastGuardOsDeterminedFailureMode", formatVa(lc.CastGuardOsDeterminedFailureMode), "CASTGuard OS-determined failure mode value/pointer (undocumented)."));
  out.push(renderLoadConfigDefinitionRow("GuardMemcpyFunctionPointer", formatVa(lc.GuardMemcpyFunctionPointer), "CFG: guard memcpy function pointer used by some toolchains/runtime checks."));
  out.push(renderLoadConfigDefinitionRow("UmaFunctionPointers", formatVa(lc.UmaFunctionPointers), "Pointer to UMA function pointers (undocumented)."));
  out.push(renderDefinitionRow("GuardFlags", renderLoadConfigGuardFlags(lc), "Control Flow Guard related flags."));
};

export function renderLoadConfig(pe: PeWindowsParseResult, out: string[]): void {
  if (!pe.loadcfg) return;
  const lc = pe.loadcfg;
  const imageBase = pe.opt.ImageBase;
  const pointerWidth = pe.opt.Magic === PE32_PLUS_OPTIONAL_HEADER_MAGIC ? 16 : 8;
  const formatVa = (value: bigint): string =>
    value === 0n ? "-" : formatPointerHex(value, pointerWidth);

  out.push(renderPeSectionStart("Load Config", `v${lc.Major}.${lc.Minor}`));
  if (lc.warnings?.length) {
    out.push(`<div class="smallNote" style="color:var(--warn-fg)">${escapeHtml(lc.warnings.join("; "))}</div>`);
  }
  if (lc.notes?.length) {
    out.push(`<div class="smallNote">${escapeHtml(lc.notes.join("; "))}</div>`);
  }
  out.push(`<dl>`);
  renderLoadConfigCoreFields(lc, formatVa, out);
  renderLoadConfigGuardFields(lc, formatVa, out);
  renderLoadConfigExtendedFields(lc, formatVa, out);
  out.push(`</dl>`);
  out.push(renderLoadConfigChecks(lc));

  if (lc.dynamicRelocations) {
    out.push(renderLoadConfigDynamicRelocations(lc.dynamicRelocations));
  }
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
  ], pe.sections, imageBase, pointerWidth));
  out.push(renderPeSectionEnd());
}
