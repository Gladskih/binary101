"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { collectLoadConfigChecks } from "../../analyzers/pe/load-config/checks.js";
import type {
  PeLoadConfig,
  PeLoadConfigCheck,
  PeLoadConfigTable,
  PeLoadConfigTableEntry
} from "../../analyzers/pe/load-config/index.js";
import { createPeLoadConfigResult } from "../../analyzers/pe/load-config/result.js";
import type { PeImportLinkingResult } from "../../analyzers/pe/imports/linking.js";
import { inlinePeSectionName } from "../../analyzers/pe/sections/name.js";
import type { PeSection, PeWindowsOptionalHeader } from "../../analyzers/pe/types.js";

// Microsoft PE format documents 0x00400000 as the historical PE32 executable ImageBase.
const PE32_DEFAULT_IMAGE_BASE = 0x400000n;
const CFG_TABLE_RVA = 0x1000;
const CFG_TABLE_VA = PE32_DEFAULT_IMAGE_BASE + BigInt(CFG_TABLE_RVA);
const CFG_TARGET_RVA = 0x1010;

// Microsoft PE GuardFlags: CF_FUNCTION_TABLE_PRESENT says the GFIDS table is present.
const IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT = 0x00000400;

const makeOptionalHeader = (dllCharacteristics = 0): PeWindowsOptionalHeader =>
  ({
    Magic: 0x10b, // Microsoft PE Optional Header magic for PE32.
    ImageBase: PE32_DEFAULT_IMAGE_BASE,
    DllCharacteristics: dllCharacteristics,
    SizeOfImage: 0x5000, // Synthetic image bound large enough to contain the CFG fixture section.
    SizeOfHeaders: 0x200 // Synthetic PE header span used by existing parser fixtures.
  }) as PeWindowsOptionalHeader;

// PE section flags: CNT_CODE | MEM_EXECUTE | MEM_READ.
const makeTextSection = (characteristics = 0x60000020): PeSection => ({
  name: inlinePeSectionName(".text"),
  virtualSize: 0x3000,
  virtualAddress: CFG_TABLE_RVA,
  sizeOfRawData: 0x3000,
  pointerToRawData: 0x200,
  characteristics
});

const makeLoadConfig = (overrides: Partial<PeLoadConfig>): PeLoadConfig => ({
  ...createPeLoadConfigResult(),
  ...overrides
});

const makeGuardFidTable = (
  entries: PeLoadConfigTableEntry[],
  entrySize = Uint32Array.BYTES_PER_ELEMENT
): PeLoadConfigTable => ({
  kind: "guardFid",
  name: "GuardCFFunctionTable",
  tableVa: CFG_TABLE_VA,
  tableRva: CFG_TABLE_RVA,
  declaredCount: entries.length,
  entrySize,
  truncated: false,
  entries
});

const expectCheckStatus = (
  checks: PeLoadConfigCheck[],
  title: string,
  status: PeLoadConfigCheck["status"]
): void => {
  assert.ok(
    checks.some(check => check.title === title && check.status === status),
    `${title} should be ${status}`
  );
};

void test("collectLoadConfigChecks passes coherent CFG table metadata", () => {
  const checks = collectLoadConfigChecks(
    makeLoadConfig({
      // PE GuardFlags: CF_INSTRUMENTED plus CF_FUNCTION_TABLE_PRESENT.
      GuardFlags: 0x00000100 | IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT,
      GuardCFFunctionTable: CFG_TABLE_VA,
      GuardCFFunctionCount: 2,
      tables: {
        guardFid: makeGuardFidTable([
          { index: 0, rva: CFG_TARGET_RVA },
          { index: 1, rva: CFG_TARGET_RVA + 0x10 }
        ])
      }
    }),
    makeOptionalHeader(0x4000 | 0x0040), // PE DllCharacteristics: GUARD_CF plus DYNAMIC_BASE.
    0x014c, // Microsoft PE Machine Types: IMAGE_FILE_MACHINE_I386.
    [makeTextSection()],
    0,
    null
  );
  expectCheckStatus(checks, "CFG header agreement", "pass");
  expectCheckStatus(checks, "GuardCFFunctionTable bounds", "pass");
  expectCheckStatus(checks, "GFIDS metadata flags", "pass");
});

void test("collectLoadConfigChecks reports CFG metadata and header mismatches", () => {
  const checks = collectLoadConfigChecks(
    makeLoadConfig({
      // PE GuardFlags high nibble encodes 1 extra GFIDS metadata byte, making 5-byte entries.
      GuardFlags: IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT | 0x10000000,
      GuardCFFunctionTable: CFG_TABLE_VA,
      GuardCFFunctionCount: 2,
      Reserved2: 1,
      tables: {
        guardFid: makeGuardFidTable([
          { index: 0, rva: CFG_TARGET_RVA + 1, metadataBytes: [0] },
          // Microsoft CFG metadata documents only bits 0 and 1; bit 7 is intentionally unknown.
          { index: 1, rva: CFG_TARGET_RVA, metadataBytes: [0x80], unknownGfidsFlagBits: 0x80 }
        ], 5)
      }
    }),
    makeOptionalHeader(0x4000), // PE DllCharacteristics: GUARD_CF.
    0x8664, // Microsoft PE Machine Types: IMAGE_FILE_MACHINE_AMD64.
    [makeTextSection()],
    0,
    null
  );
  expectCheckStatus(checks, "CFG header agreement", "fail");
  expectCheckStatus(checks, "GuardCFFunctionTable sorted RVAs", "fail");
  expectCheckStatus(checks, "GFIDS metadata flags", "fail");
  expectCheckStatus(checks, "GFIDS 16-byte alignment", "fail");
  expectCheckStatus(checks, "Reserved Load Config fields", "fail");
});

void test("collectLoadConfigChecks fails when a declared CFG table was not decoded", () => {
  const checks = collectLoadConfigChecks(
    makeLoadConfig({
      GuardFlags: IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT,
      GuardCFFunctionTable: CFG_TABLE_VA,
      GuardCFFunctionCount: 1
    }),
    makeOptionalHeader(),
    0x8664, // Microsoft PE Machine Types: IMAGE_FILE_MACHINE_AMD64.
    [makeTextSection()],
    0,
    null
  );
  expectCheckStatus(checks, "GuardCFFunctionTable decoded table", "fail");
});

void test("collectLoadConfigChecks rejects SafeSEH on non-x86 images and with NO_SEH", () => {
  const checks = collectLoadConfigChecks(
    makeLoadConfig({
      SEHandlerTable: CFG_TABLE_VA,
      SEHandlerCount: 1
    }),
    makeOptionalHeader(0x0400), // PE DllCharacteristics: NO_SEH.
    0x8664, // Microsoft PE Machine Types: IMAGE_FILE_MACHINE_AMD64.
    [makeTextSection()],
    0,
    null
  );
  expectCheckStatus(checks, "SafeSEH architecture", "fail");
  expectCheckStatus(checks, "SafeSEH vs NO_SEH", "fail");
});

void test("collectLoadConfigChecks flags writable CFG pointer slots", () => {
  const checks = collectLoadConfigChecks(
    makeLoadConfig({ GuardCFCheckFunctionPointer: CFG_TABLE_VA }),
    makeOptionalHeader(),
    0x8664, // Microsoft PE Machine Types: IMAGE_FILE_MACHINE_AMD64.
    [makeTextSection(0xe0000020)], // PE section flags: code/read/execute plus MEM_WRITE.
    0,
    null
  );
  expectCheckStatus(checks, "GuardCFCheckFunctionPointer read-only slot", "fail");
});

void test("collectLoadConfigChecks rejects reserved metadata in non-GFIDS CFG tables", () => {
  const checks = collectLoadConfigChecks(
    makeLoadConfig({
      GuardAddressTakenIatEntryTable: CFG_TABLE_VA,
      GuardAddressTakenIatEntryCount: 1,
      tables: {
        guardIat: {
          kind: "guardIat",
          name: "GuardAddressTakenIatEntryTable",
          tableVa: CFG_TABLE_VA,
          tableRva: CFG_TABLE_RVA,
          declaredCount: 1,
          entrySize: 5,
          truncated: false,
          entries: [{ index: 0, rva: CFG_TARGET_RVA, metadataBytes: [0x80] }]
        }
      }
    }),
    makeOptionalHeader(),
    0x8664, // Microsoft PE Machine Types: IMAGE_FILE_MACHINE_AMD64.
    [makeTextSection()],
    0,
    null
  );
  expectCheckStatus(checks, "Reserved CFG table metadata", "fail");
});

void test("collectLoadConfigChecks fails unconfirmed protected delay-load IAT layout", () => {
  const importLinking: PeImportLinkingResult = {
    modules: [{
      moduleKey: "delay.dll",
      imports: [],
      boundImports: [],
      delayImports: [],
      findings: [{
        code: "delay-iat-own-section-mismatch",
        severity: "warning",
        message: "mismatch"
      }]
    }],
    inferredEagerIat: null
  };
  const checks = collectLoadConfigChecks(
    makeLoadConfig({
      // PE GuardFlags: PROTECT_DELAYLOAD_IAT plus DELAYLOAD_IAT_IN_ITS_OWN_SECTION.
      GuardFlags: 0x00001000 | 0x00002000
    }),
    makeOptionalHeader(),
    0x8664, // Microsoft PE Machine Types: IMAGE_FILE_MACHINE_AMD64.
    [makeTextSection()],
    1,
    importLinking
  );
  expectCheckStatus(checks, "Delay-load IAT protection", "fail");
});
