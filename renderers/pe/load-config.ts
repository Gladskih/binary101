"use strict";

import { hex, isoOrDash } from "../../binary-utils.js";
import { dd, safe } from "../../html-utils.js";
import { GUARD_FLAGS } from "../../analyzers/pe/constants.js";
import type { PeParseResult } from "../../analyzers/pe/index.js";
import type { PeLoadConfig } from "../../analyzers/pe/load-config.js";

const formatVa = (value: number | bigint, isPlus: boolean): string => {
  if (!value) return "-";
  return isPlus ? `0x${BigInt(value).toString(16)}` : hex(Number(value), 8);
};

const renderGuardFlags = (lc: PeLoadConfig, out: string[]): void => {
  if (typeof lc.GuardFlags !== "number") return;
  const guardFlags = lc.GuardFlags >>> 0;
  const stride = (guardFlags >>> 28) & 0xf;
  const flags = GUARD_FLAGS.filter(([bit]) => (guardFlags & bit) !== 0).map(([, name]) => name);
  if (stride > 0) flags.push(`CF_FUNCTION_TABLE_SIZE_${4 + stride}BYTES`);
  out.push(
    dd(
      "GuardFlags",
      guardFlags ? hex(guardFlags, 8) : "0",
      flags.length ? flags.join(", ") : "No CFG-related flags set."
    )
  );
};

export function renderLoadConfig(pe: PeParseResult, out: string[]): void {
  if (!pe.loadcfg) return;
  const lc = pe.loadcfg;

  const formatRvaAsVa = (rva: number): string => {
    if (!Number.isSafeInteger(rva) || rva <= 0) return "-";
    const base = pe.opt.ImageBase;
    if (pe.opt.isPlus) return `0x${(BigInt(base) + BigInt(rva >>> 0)).toString(16)}`;
    return hex((base + (rva >>> 0)) >>> 0, 8);
  };

  const renderAddressList = (title: string, rvas: number[], note?: string): void => {
    const unique = [...new Set(rvas.map(rva => rva >>> 0))];
    unique.sort((a, b) => a - b);
    out.push(
      `<details><summary style="cursor:pointer;padding:.25rem .5rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg)">${safe(
        `${title} (${unique.length})`
      )}</summary>`
    );
    if (note) {
      out.push(`<div class="smallNote" style="margin:.35rem 0 0 0">${safe(note)}</div>`);
    }
    out.push(
      `<pre style="margin:.35rem 0 0 0;padding:.5rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg);white-space:pre;overflow:auto">${safe(
        unique.map(rva => formatRvaAsVa(rva)).join("\n")
      )}</pre></details>`
    );
  };

  out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Load Config</h4>`);
  if (lc.warnings?.length) {
    out.push(`<div class="smallNote" style="color:var(--warn-fg)">${safe(lc.warnings.join("; "))}</div>`);
  }
  out.push(`<dl>`);
  out.push(dd("Size", hex(lc.Size, 8), "Structure size of IMAGE_LOAD_CONFIG_DIRECTORY."));
  out.push(dd("TimeDateStamp", isoOrDash(lc.TimeDateStamp), "Build timestamp for load config data."));
  out.push(dd("Version", `${lc.Major}.${lc.Minor}`, "Load config version (varies between OS/toolchain versions)."));
  out.push(dd("GlobalFlagsClear", hex(lc.GlobalFlagsClear, 8), "Global loader flags to clear for the process."));
  out.push(dd("GlobalFlagsSet", hex(lc.GlobalFlagsSet, 8), "Global loader flags to set for the process."));
  out.push(
    dd(
      "CriticalSectionDefaultTimeout",
      hex(lc.CriticalSectionDefaultTimeout, 8),
      "Default critical section timeout used by the runtime/loader."
    )
  );
  out.push(
    dd(
      "DeCommitFreeBlockThreshold",
      formatVa(lc.DeCommitFreeBlockThreshold, pe.opt.isPlus),
      "Heap free-block threshold for decommit (legacy)."
    )
  );
  out.push(
    dd(
      "DeCommitTotalFreeThreshold",
      formatVa(lc.DeCommitTotalFreeThreshold, pe.opt.isPlus),
      "Heap total-free threshold for decommit (legacy)."
    )
  );
  out.push(dd("LockPrefixTable", formatVa(lc.LockPrefixTable, pe.opt.isPlus), "Pointer to the lock prefix table (legacy)."));
  out.push(
    dd(
      "MaximumAllocationSize",
      formatVa(lc.MaximumAllocationSize, pe.opt.isPlus),
      "Maximum allocation size used by the heap/loader (legacy)."
    )
  );
  out.push(
    dd(
      "VirtualMemoryThreshold",
      formatVa(lc.VirtualMemoryThreshold, pe.opt.isPlus),
      "Virtual memory threshold used by the heap/loader (legacy)."
    )
  );
  out.push(dd("ProcessHeapFlags", hex(lc.ProcessHeapFlags, 8), "Flags used when creating the default process heap."));
  out.push(
    dd("ProcessAffinityMask", formatVa(lc.ProcessAffinityMask, pe.opt.isPlus), "Preferred processor affinity mask (legacy).")
  );
  out.push(dd("CSDVersion", hex(lc.CSDVersion, 4), "CSD (Service Pack) version field (legacy)."));
  out.push(dd("DependentLoadFlags", hex(lc.DependentLoadFlags, 4), "Flags affecting how dependent DLLs are loaded."));
  out.push(dd("EditList", formatVa(lc.EditList, pe.opt.isPlus), "Pointer to an edit list (hotpatch/legacy)."));
  out.push(dd("SecurityCookie", formatVa(lc.SecurityCookie, pe.opt.isPlus), "Address of the GS cookie (stack guard)."));
  out.push(dd("SEHandlerTable", formatVa(lc.SEHandlerTable, pe.opt.isPlus), "SafeSEH handler table (x86 only)."));
  out.push(dd("SEHandlerCount", String(lc.SEHandlerCount ?? "-"), "Number of SafeSEH handlers (x86)."));
  out.push(
    dd(
      "GuardCFCheckFunctionPointer",
      formatVa(lc.GuardCFCheckFunctionPointer, pe.opt.isPlus),
      "CFG: guard check function pointer used to validate indirect call/jump targets."
    )
  );
  out.push(
    dd(
      "GuardCFDispatchFunctionPointer",
      formatVa(lc.GuardCFDispatchFunctionPointer, pe.opt.isPlus),
      "CFG: guard dispatch function pointer used for certain indirect control transfers."
    )
  );
  out.push(dd("GuardCFFunctionTable", formatVa(lc.GuardCFFunctionTable, pe.opt.isPlus), "CFG function table VA."));
  out.push(dd("GuardCFFunctionCount", String(lc.GuardCFFunctionCount ?? "-"), "Number of CFG functions listed."));
  out.push(dd("CodeIntegrity.Flags", hex(lc.CodeIntegrity.Flags, 4), "IMAGE_LOAD_CONFIG_CODE_INTEGRITY flags."));
  out.push(dd("CodeIntegrity.Catalog", hex(lc.CodeIntegrity.Catalog, 4), "Catalog identifier used by code integrity."));
  out.push(dd("CodeIntegrity.CatalogOffset", hex(lc.CodeIntegrity.CatalogOffset, 8), "Catalog offset used by code integrity."));
  out.push(dd("CodeIntegrity.Reserved", hex(lc.CodeIntegrity.Reserved, 8), "Reserved (code integrity)."));
  out.push(
    dd(
      "VolatileMetadataPointer",
      formatVa(lc.VolatileMetadataPointer, pe.opt.isPlus),
      "Pointer to optional 'volatile metadata' referenced from the load config (format is not documented in Win32 API docs)."
    )
  );
  out.push(
    dd(
      "GuardEHContinuationTable",
      formatVa(lc.GuardEHContinuationTable, pe.opt.isPlus),
      "CFG: VA of EH continuation table (valid exception-handling continuation targets)."
    )
  );
  out.push(dd("GuardEHContinuationCount", String(lc.GuardEHContinuationCount ?? "-"), "Number of EH continuation targets in the table."));
  out.push(
    dd(
      "GuardLongJumpTargetTable",
      formatVa(lc.GuardLongJumpTargetTable, pe.opt.isPlus),
      "CFG: VA of longjmp target table (valid longjmp destinations)."
    )
  );
  out.push(dd("GuardLongJumpTargetCount", String(lc.GuardLongJumpTargetCount ?? "-"), "Number of longjmp targets in the table."));
  out.push(
    dd(
      "GuardAddressTakenIatEntryTable",
      formatVa(lc.GuardAddressTakenIatEntryTable, pe.opt.isPlus),
      "CFG: VA of the address-taken IAT entry table (IAT slots whose imported addresses may be used as function-pointer values, so they remain valid indirect-call targets)."
    )
  );
  out.push(
    dd(
      "GuardAddressTakenIatEntryCount",
      String(lc.GuardAddressTakenIatEntryCount ?? "-"),
      "Number of entries in GuardAddressTakenIatEntryTable."
    )
  );
  out.push(dd("DynamicValueRelocTable", formatVa(lc.DynamicValueRelocTable, pe.opt.isPlus), "Pointer to the dynamic relocations table (if used)."));
  out.push(dd("CHPEMetadataPointer", formatVa(lc.CHPEMetadataPointer, pe.opt.isPlus), "Pointer to CHPE metadata (used by ARM64EC/CHPE images)."));
  out.push(dd("GuardRFFailureRoutine", formatVa(lc.GuardRFFailureRoutine, pe.opt.isPlus), "GuardRF failure routine pointer (if present)."));
  out.push(
    dd(
      "GuardRFFailureRoutineFunctionPointer",
      formatVa(lc.GuardRFFailureRoutineFunctionPointer, pe.opt.isPlus),
      "Pointer to GuardRF failure routine function pointer."
    )
  );
  out.push(
    dd(
      "DynamicValueRelocTableOffset",
      hex(lc.DynamicValueRelocTableOffset, 8),
      "Offset of the dynamic relocations table within DynamicValueRelocTableSection."
    )
  );
  out.push(
    dd(
      "DynamicValueRelocTableSection",
      hex(lc.DynamicValueRelocTableSection, 4),
      "Section index for DynamicValueRelocTableOffset (1-based)."
    )
  );
  out.push(dd("Reserved2", hex(lc.Reserved2, 4), "Reserved."));
  out.push(
    dd(
      "GuardRFVerifyStackPointerFunctionPointer",
      formatVa(lc.GuardRFVerifyStackPointerFunctionPointer, pe.opt.isPlus),
      "GuardRF verify stack pointer function pointer."
    )
  );
  out.push(dd("HotPatchTableOffset", hex(lc.HotPatchTableOffset, 8), "Offset of hotpatch data (if present)."));
  out.push(dd("Reserved3", hex(lc.Reserved3, 8), "Reserved."));
  out.push(
    dd(
      "EnclaveConfigurationPointer",
      formatVa(lc.EnclaveConfigurationPointer, pe.opt.isPlus),
      "Pointer to enclave configuration (if present)."
    )
  );
  out.push(dd("GuardXFGCheckFunctionPointer", formatVa(lc.GuardXFGCheckFunctionPointer, pe.opt.isPlus), "XFG: extended-flow-guard check function pointer."));
  out.push(dd("GuardXFGDispatchFunctionPointer", formatVa(lc.GuardXFGDispatchFunctionPointer, pe.opt.isPlus), "XFG: extended-flow-guard dispatch function pointer."));
  out.push(dd("GuardXFGTableDispatchFunctionPointer", formatVa(lc.GuardXFGTableDispatchFunctionPointer, pe.opt.isPlus), "XFG: table dispatch function pointer."));
  out.push(
    dd(
      "CastGuardOsDeterminedFailureMode",
      formatVa(lc.CastGuardOsDeterminedFailureMode, pe.opt.isPlus),
      "CASTGuard OS-determined failure mode value/pointer (undocumented)."
    )
  );
  out.push(dd("GuardMemcpyFunctionPointer", formatVa(lc.GuardMemcpyFunctionPointer, pe.opt.isPlus), "CFG: guard memcpy function pointer used by some toolchains/runtime checks."));
  out.push(dd("UmaFunctionPointers", formatVa(lc.UmaFunctionPointers, pe.opt.isPlus), "Pointer to UMA function pointers (undocumented)."));
  renderGuardFlags(lc, out);
  out.push(`</dl>`);

  if (lc.dynamicRelocations) {
    const dr = lc.dynamicRelocations;
    const typeList = dr.entries.map(e => (e.kind === "v1" ? e.symbol : e.symbol)).filter(v => v);
    const types = [...new Set(typeList)].sort((a, b) => a - b);
    out.push(
      `<details><summary style="cursor:pointer;padding:.25rem .5rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg)">DynamicRelocations (v${dr.version}, ${dr.entries.length} entr${dr.entries.length === 1 ? "y" : "ies"})</summary>`
    );
    if (dr.warnings?.length) {
      out.push(`<div class="smallNote" style="margin:.35rem 0 0 0;color:var(--warn-fg)">${safe(dr.warnings.join("; "))}</div>`);
    }
    out.push(`<dl style="margin:.35rem 0 0 0">`);
    out.push(dd("Version", hex(dr.version, 8), "Dynamic relocation table version."));
    out.push(dd("DataSize", hex(dr.dataSize, 8), "Size of the dynamic relocation table payload in bytes."));
    out.push(
      dd(
        "Types",
        types.length ? safe(types.map(t => hex(t, 0)).join(", ")) : "-",
        "Unique relocation symbol/type values present."
      )
    );
    out.push(`</dl>`);
    if (dr.entries.length) {
      out.push(
        `<table class="table" style="margin-top:.35rem"><thead><tr><th>#</th><th>Kind</th><th>Symbol</th><th>Size</th><th>Available</th></tr></thead><tbody>`
      );
      dr.entries.forEach((entry, index) => {
        const kind = entry.kind;
        const symbol = entry.symbol ? hex(entry.symbol, 0) : "-";
        const size = entry.kind === "v1" ? hex(entry.baseRelocSize, 8) : hex(entry.fixupInfoSize, 8);
        const available = hex(entry.availableBytes, 8);
        out.push(`<tr><td>${index + 1}</td><td>${safe(kind)}</td><td>${safe(symbol)}</td><td>${safe(size)}</td><td>${safe(available)}</td></tr>`);
      });
      out.push(`</tbody></table>`);
    }
    out.push(`</details>`);
  }

  if (lc.tables?.safeSehHandlerRvas?.length) {
    renderAddressList("SEHTable", lc.tables.safeSehHandlerRvas, "SafeSEH handlers (x86 only).");
  }
  if (lc.tables?.guardFidRvas?.length) {
    renderAddressList("GuardFidTable", lc.tables.guardFidRvas, "CFG function targets (GFIDS).");
  }
  if (lc.tables?.guardIatRvas?.length) {
    renderAddressList(
      "GuardIatTable",
      lc.tables.guardIatRvas,
      "Address-taken IAT entries (IAT slots whose imported addresses may be used as function pointers under CFG)."
    );
  }
  if (lc.tables?.guardLongJumpTargetRvas?.length) {
    renderAddressList("GuardLongJumpTable", lc.tables.guardLongJumpTargetRvas, "Valid longjmp destinations under CFG.");
  }
  if (lc.tables?.guardEhContinuationRvas?.length) {
    renderAddressList("GuardEHContTable", lc.tables.guardEhContinuationRvas, "Valid exception continuation targets under CFG.");
  }

  out.push(`</section>`);
}
