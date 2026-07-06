"use strict";

import { readLoadConfigPointerRva, type PeLoadConfig, type PeLoadConfigCheck } from "./index.js";
import type { PeImportLinkingResult } from "../imports/linking.js";
import { IMAGE_FILE_MACHINE_I386 } from "../../coff/machine.js";
import { getCanonicalPeMachine } from "../machine.js";
import type { PeSection, PeWindowsOptionalHeader } from "../types.js";

const IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE = 0x0040;
const IMAGE_DLL_CHARACTERISTICS_NO_SEH = 0x0400;
const IMAGE_DLL_CHARACTERISTICS_GUARD_CF = 0x4000;
const IMAGE_GUARD_CF_INSTRUMENTED = 0x00000100;
const IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT = 0x00000400;
const IMAGE_GUARD_PROTECT_DELAYLOAD_IAT = 0x00001000;
const IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION = 0x00002000;
const IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT = 0x00010000;
const IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT = 0x00004000;
const IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION = 0x00008000;
const IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT = 0x00400000;
const IMAGE_SCN_MEM_WRITE = 0x80000000;

const addCheck = (
  checks: PeLoadConfigCheck[],
  status: PeLoadConfigCheck["status"],
  title: string,
  detail: string,
  source?: string
): void => {
  checks.push({ status, title, detail, ...(source ? { source } : {}) });
};

const hasFlag = (value: number, flag: number): boolean => ((value >>> 0) & flag) !== 0;

const findSectionContainingRva = (sections: PeSection[], rva: number): PeSection | null => {
  const normalizedRva = rva >>> 0;
  for (const section of sections) {
    const start = section.virtualAddress >>> 0;
    const size = (section.virtualSize >>> 0) || (section.sizeOfRawData >>> 0);
    if (normalizedRva >= start && normalizedRva < start + size) return section;
  }
  return null;
};

const isSortedUnique = (rvas: number[]): boolean =>
  rvas.every((rva, index) => index === 0 || rva > (rvas[index - 1] ?? 0));

const checkStructuredTable = (
  checks: PeLoadConfigCheck[],
  lc: PeLoadConfig,
  tableName: keyof NonNullable<PeLoadConfig["tables"]>,
  flagName?: string,
  flag?: number
): void => {
  const table = lc.tables?.[tableName];
  if (!table) return;
  const rvas = table.entries.map(entry => entry.rva);
  addCheck(
    checks,
    table.truncated || table.entries.length < table.declaredCount ? "fail" : "pass",
    `${table.name} bounds`,
    `${table.entries.length}/${table.declaredCount} entries read; entry size ${table.entrySize} bytes.`
  );
  if (rvas.length > 1) {
    addCheck(
      checks,
      isSortedUnique(rvas) ? "pass" : "fail",
      `${table.name} sorted RVAs`,
      "Tables used by CFG/SafeSEH should contain sorted unique RVAs."
    );
  }
  if (flagName && flag != null) {
    const present = hasFlag(lc.GuardFlags, flag);
    const hasEntries = table.declaredCount > 0 || table.tableVa !== 0n;
    addCheck(
      checks,
      present === hasEntries ? "pass" : "fail",
      `${flagName} consistency`,
      present
        ? `${flagName} is set; ${table.name} should describe the corresponding table.`
        : `${flagName} is clear; ${table.name} should normally be absent.`
    );
  }
};

const checkDeclaredTableAvailable = (
  checks: PeLoadConfigCheck[],
  lc: PeLoadConfig,
  tableName: keyof NonNullable<PeLoadConfig["tables"]>,
  displayName: string,
  count: number,
  tableVa: bigint
): void => {
  if (count <= 0 && tableVa === 0n) return;
  addCheck(
    checks,
    lc.tables?.[tableName] ? "pass" : "fail",
    `${displayName} decoded table`,
    count > 0
      ? `${displayName} declares ${count} entries; decoded table details should be available.`
      : `${displayName} has a pointer but no declared entries.`
  );
};

const checkCfgMetadata = (checks: PeLoadConfigCheck[], lc: PeLoadConfig): void => {
  const guardFid = lc.tables?.guardFid;
  const unknownGfids = guardFid?.entries.filter(entry => (entry.unknownGfidsFlagBits ?? 0) !== 0) ?? [];
  if (guardFid) {
    addCheck(
      checks,
      unknownGfids.length ? "fail" : "pass",
      "GFIDS metadata flags",
      unknownGfids.length
        ? `${unknownGfids.length} GFIDS entries contain unknown metadata flag bits.`
        : "GFIDS metadata uses only documented FID_SUPPRESSED/EXPORT_SUPPRESSED bits."
    );
    const misaligned = guardFid.entries.filter(entry => (entry.rva & 0xf) !== 0);
    addCheck(
      checks,
      misaligned.length ? "fail" : "pass",
      "GFIDS 16-byte alignment",
      misaligned.length
        ? `${misaligned.length} GFIDS RVAs are not 16-byte aligned.`
        : "All decoded GFIDS RVAs are 16-byte aligned."
    );
  }
  const reservedTables = [
    lc.tables?.guardIat,
    lc.tables?.guardLongJumpTarget,
    lc.tables?.guardEhContinuation
  ].filter(table => table != null);
  const reservedNonZero = reservedTables.flatMap(table =>
    table.entries.filter(entry => entry.metadataBytes?.some(byte => byte !== 0))
  );
  if (reservedTables.length) {
    addCheck(
      checks,
      reservedNonZero.length ? "fail" : "pass",
      "Reserved CFG table metadata",
      reservedNonZero.length
        ? `${reservedNonZero.length} non-GFIDS entries contain non-zero reserved metadata bytes.`
        : "Non-GFIDS CFG table metadata bytes are zero or absent."
    );
  }
};

const checkPointerSlot = (
  checks: PeLoadConfigCheck[],
  sections: PeSection[],
  imageBase: bigint,
  name: string,
  pointerVa: bigint
): void => {
  const rva = readLoadConfigPointerRva(imageBase, pointerVa);
  if (pointerVa === 0n || rva == null) return;
  const section = findSectionContainingRva(sections, rva);
  if (!section) {
    addCheck(checks, "info", `${name} section`, "Pointer slot RVA does not resolve to a section.");
    return;
  }
  addCheck(
    checks,
    (section.characteristics & IMAGE_SCN_MEM_WRITE) === 0 ? "pass" : "fail",
    `${name} read-only slot`,
    "CFG pointer slots should be stored in non-writable memory for the loader patch to be meaningful.",
    "Microsoft PE CFG metadata"
  );
};

const checkDelayLoad = (
  checks: PeLoadConfigCheck[],
  lc: PeLoadConfig,
  delayImportCount: number,
  importLinking: PeImportLinkingResult | null
): void => {
  const protects = hasFlag(lc.GuardFlags, IMAGE_GUARD_PROTECT_DELAYLOAD_IAT);
  const ownSection = hasFlag(lc.GuardFlags, IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION);
  if (!protects && !ownSection) return;
  if (!delayImportCount) {
    addCheck(checks, "info", "Delay-load guard flags", "Delay-load guard flags are set, but no delay imports were parsed.");
    return;
  }
  const findings = importLinking?.modules.flatMap(module => module.findings ?? []) ?? [];
  const hasConfirmed = findings.some(finding =>
    finding.code === "protected-delay-iat-own-section" ||
    finding.code === "protected-delay-iat-separate-section"
  );
  const hasMismatch = findings.some(finding => finding.code === "delay-iat-own-section-mismatch");
  addCheck(
    checks,
    hasMismatch || !hasConfirmed ? "fail" : "pass",
    "Delay-load IAT protection",
    hasConfirmed
      ? "Delay-load IAT layout was confirmed against Load Config GuardFlags."
      : "Load Config advertises protected delay-load IAT handling, but no protected layout was confirmed."
  );
};

export const collectLoadConfigChecks = (
  lc: PeLoadConfig,
  opt: PeWindowsOptionalHeader,
  coffMachine: number,
  sections: PeSection[],
  delayImportCount: number,
  importLinking: PeImportLinkingResult | null
): PeLoadConfigCheck[] => {
  const checks: PeLoadConfigCheck[] = [];
  const canonicalMachine = getCanonicalPeMachine(coffMachine);
  const guardCfHeader = hasFlag(opt.DllCharacteristics, IMAGE_DLL_CHARACTERISTICS_GUARD_CF);
  const cfgInstrumented = hasFlag(lc.GuardFlags, IMAGE_GUARD_CF_INSTRUMENTED);
  addCheck(
    checks,
    guardCfHeader === cfgInstrumented ? "pass" : "fail",
    "CFG header agreement",
    "IMAGE_DLLCHARACTERISTICS_GUARD_CF and IMAGE_GUARD_CF_INSTRUMENTED should agree."
  );
  addCheck(
    checks,
    !cfgInstrumented || hasFlag(opt.DllCharacteristics, IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE) ? "pass" : "fail",
    "CFG with ASLR",
    "Microsoft recommends enabling ASLR/DYNAMIC_BASE for user-mode CFG images."
  );
  checkDeclaredTableAvailable(checks, lc, "guardFid", "GuardCFFunctionTable", lc.GuardCFFunctionCount, lc.GuardCFFunctionTable);
  checkDeclaredTableAvailable(checks, lc, "guardIat", "GuardAddressTakenIatEntryTable", lc.GuardAddressTakenIatEntryCount, lc.GuardAddressTakenIatEntryTable);
  checkDeclaredTableAvailable(checks, lc, "guardLongJumpTarget", "GuardLongJumpTargetTable", lc.GuardLongJumpTargetCount, lc.GuardLongJumpTargetTable);
  checkDeclaredTableAvailable(checks, lc, "guardEhContinuation", "GuardEHContinuationTable", lc.GuardEHContinuationCount, lc.GuardEHContinuationTable);
  checkStructuredTable(checks, lc, "guardFid", "CF_FUNCTION_TABLE_PRESENT", IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT);
  checkStructuredTable(
    checks,
    lc,
    "guardLongJumpTarget",
    "CF_LONGJUMP_TABLE_PRESENT",
    IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT
  );
  checkStructuredTable(
    checks,
    lc,
    "guardEhContinuation",
    "EH_CONTINUATION_TABLE_PRESENT",
    IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT
  );
  checkStructuredTable(checks, lc, "guardIat");
  checkStructuredTable(checks, lc, "safeSehHandler");
  if (lc.SEHandlerCount > 0 || lc.SEHandlerTable !== 0n) {
    addCheck(
      checks,
      canonicalMachine === IMAGE_FILE_MACHINE_I386 ? "pass" : "fail",
      "SafeSEH architecture",
      "SafeSEH is documented for x86 images only."
    );
    addCheck(
      checks,
      hasFlag(opt.DllCharacteristics, IMAGE_DLL_CHARACTERISTICS_NO_SEH) ? "fail" : "pass",
      "SafeSEH vs NO_SEH",
      "NO_SEH says no structured exception handling is used, so a SafeSEH table is contradictory."
    );
  }
  if (hasFlag(lc.GuardFlags, IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT)) {
    addCheck(
      checks,
      lc.tables?.guardIat ? "pass" : "info",
      "Export suppression IAT metadata",
      "Export suppression metadata uses GuardAddressTakenIatEntryTable; the count may legitimately be zero."
    );
  }
  if (hasFlag(lc.GuardFlags, IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION)) {
    addCheck(checks, "info", "Export suppression opt-in", "CFG export suppression is mainly meaningful for EXEs.");
  }
  addCheck(
    checks,
    lc.Reserved2 === 0 && lc.Reserved3 === 0 ? "pass" : "fail",
    "Reserved Load Config fields",
    "Reserved2 and Reserved3 should be zero."
  );
  checkCfgMetadata(checks, lc);
  checkPointerSlot(checks, sections, opt.ImageBase, "GuardCFCheckFunctionPointer", lc.GuardCFCheckFunctionPointer);
  checkPointerSlot(checks, sections, opt.ImageBase, "GuardCFDispatchFunctionPointer", lc.GuardCFDispatchFunctionPointer);
  checkDelayLoad(checks, lc, delayImportCount, importLinking);
  return checks;
};
