"use strict";

import type { PeImportLinkingResult } from "../../analyzers/pe/import-linking.js";
import type { PeImportParseResult } from "../../analyzers/pe/imports.js";
import type { PeIatDirectory } from "../../analyzers/pe/iat-directory.js";
import type { PeDelayImportEntry } from "../../analyzers/pe/delay-imports.js";
import type { PeBoundImportEntry } from "../../analyzers/pe/bound-imports.js";
import type { PeParseResult } from "../../analyzers/pe/index.js";
import type { PeLoadConfig } from "../../analyzers/pe/load-config/index.js";
import { analyzeImportLinking } from "../../analyzers/pe/import-linking.js";
import { createBasePe, createPeSection } from "./pe-renderer-headers-fixture.js";

export const createWritableDataSection = (
  name: string,
  virtualAddress: number,
  pointerToRawData: number
) =>
  createPeSection(name, {
    virtualAddress,
    pointerToRawData,
    // IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE.
    // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-flags
    characteristics: 0x00000040 | 0x40000000 | 0x80000000
  });

const createLoadConfig = (guardFlags: number): PeLoadConfig => ({
  Size: 0,
  TimeDateStamp: 0,
  Major: 0,
  Minor: 0,
  GlobalFlagsClear: 0,
  GlobalFlagsSet: 0,
  CriticalSectionDefaultTimeout: 0,
  DeCommitFreeBlockThreshold: 0n,
  DeCommitTotalFreeThreshold: 0n,
  LockPrefixTable: 0n,
  MaximumAllocationSize: 0n,
  VirtualMemoryThreshold: 0n,
  ProcessHeapFlags: 0,
  ProcessAffinityMask: 0n,
  CSDVersion: 0,
  DependentLoadFlags: 0,
  EditList: 0n,
  SecurityCookie: 0n,
  SEHandlerTable: 0n,
  SEHandlerCount: 0,
  GuardCFCheckFunctionPointer: 0n,
  GuardCFDispatchFunctionPointer: 0n,
  GuardCFFunctionTable: 0n,
  GuardCFFunctionCount: 0,
  CodeIntegrity: { Flags: 0, Catalog: 0, CatalogOffset: 0, Reserved: 0 },
  GuardAddressTakenIatEntryTable: 0n,
  GuardAddressTakenIatEntryCount: 0,
  GuardLongJumpTargetTable: 0n,
  GuardLongJumpTargetCount: 0,
  DynamicValueRelocTable: 0n,
  CHPEMetadataPointer: 0n,
  GuardRFFailureRoutine: 0n,
  GuardRFFailureRoutineFunctionPointer: 0n,
  DynamicValueRelocTableOffset: 0,
  DynamicValueRelocTableSection: 0,
  Reserved2: 0,
  GuardRFVerifyStackPointerFunctionPointer: 0n,
  HotPatchTableOffset: 0,
  Reserved3: 0,
  EnclaveConfigurationPointer: 0n,
  VolatileMetadataPointer: 0n,
  GuardEHContinuationTable: 0n,
  GuardEHContinuationCount: 0,
  GuardXFGCheckFunctionPointer: 0n,
  GuardXFGDispatchFunctionPointer: 0n,
  GuardXFGTableDispatchFunctionPointer: 0n,
  CastGuardOsDeterminedFailureMode: 0n,
  GuardMemcpyFunctionPointer: 0n,
  UmaFunctionPointers: 0n,
  GuardFlags: guardFlags
});

const createLinkedImports = (): PeImportParseResult => ({
  entries: [
    {
      dll: "KERNEL32.dll",
      originalFirstThunkRva: 0x1000,
      timeDateStamp: 0,
      forwarderChain: 0,
      firstThunkRva: 0x2000,
      lookupSource: "import-lookup-table",
      functions: [{ hint: 1, name: "Sleep" }]
    },
    {
      dll: "USER32.dll",
      originalFirstThunkRva: 0,
      // Patterned timestamp to distinguish raw field handling from defaults.
      timeDateStamp: 0x12345678,
      forwarderChain: 0,
      firstThunkRva: 0x2100,
      lookupSource: "iat-fallback",
      functions: [{ hint: 2, name: "MessageBoxW" }]
    }
  ]
});

const createLinkedBoundImports = (): { entries: PeBoundImportEntry[] } => ({
  entries: [
    {
      name: "KERNEL32.dll",
      TimeDateStamp: 0x01020304,
      NumberOfModuleForwarderRefs: 0
    },
    {
      name: "orphan.dll",
      TimeDateStamp: 0x05060708,
      NumberOfModuleForwarderRefs: 0
    }
  ]
});

const createLinkedDelayImports = (): { entries: PeDelayImportEntry[] } => ({
  entries: [
    {
      name: "USER32.dll",
      Attributes: 1,
      ModuleHandleRVA: 0,
      ImportAddressTableRVA: 0x2300,
      ImportNameTableRVA: 0x2400,
      BoundImportAddressTableRVA: 0,
      UnloadInformationTableRVA: 0,
      TimeDateStamp: 0,
      functions: [{ hint: 2, name: "MessageBoxW" }]
    }
  ]
});

const createLinkedIatDirectory = (): PeIatDirectory => ({
  rva: 0x2000,
  size: 0x200
});

export const createImportLinkingInputs = (): {
  imports: PeImportParseResult;
  boundImports: { entries: PeBoundImportEntry[] };
  delayImports: { entries: PeDelayImportEntry[] };
  iat: PeIatDirectory;
  loadcfg: PeLoadConfig;
} => ({
  imports: createLinkedImports(),
  boundImports: createLinkedBoundImports(),
  delayImports: createLinkedDelayImports(),
  iat: createLinkedIatDirectory(),
  // PROTECT_DELAYLOAD_IAT | DELAYLOAD_IAT_IN_ITS_OWN_SECTION.
  loadcfg: createLoadConfig(0x00001000 | 0x00002000)
});

export const createImportLinkingOwnSectionMismatchInputs = (): {
  imports: PeImportParseResult;
  boundImports: { entries: PeBoundImportEntry[] };
  delayImports: { entries: PeDelayImportEntry[] };
  iat: PeIatDirectory;
  loadcfg: PeLoadConfig;
} => ({
  imports: createLinkedImports(),
  boundImports: createLinkedBoundImports(),
  delayImports: {
    entries: [
      {
        name: "USER32.dll",
        Attributes: 1,
        ModuleHandleRVA: 0,
        ImportAddressTableRVA: 0x2008,
        ImportNameTableRVA: 0x2400,
        BoundImportAddressTableRVA: 0,
        UnloadInformationTableRVA: 0,
        TimeDateStamp: 0,
        functions: [{ hint: 2, name: "MessageBoxW" }]
      }
    ]
  },
  iat: createLinkedIatDirectory(),
  loadcfg: createLoadConfig(0x00002000)
});

export const createImportLinkingProtectedSeparateSectionInputs = (): {
  imports: PeImportParseResult;
  boundImports: { entries: PeBoundImportEntry[] };
  delayImports: { entries: PeDelayImportEntry[] };
  iat: PeIatDirectory;
  loadcfg: PeLoadConfig;
} => ({
  imports: createLinkedImports(),
  boundImports: createLinkedBoundImports(),
  delayImports: createLinkedDelayImports(),
  iat: createLinkedIatDirectory(),
  loadcfg: createLoadConfig(0x00001000)
});

export const createImportLinkingOutsideDirectoryInputs = (): {
  imports: PeImportParseResult;
  boundImports: { entries: PeBoundImportEntry[] };
  delayImports: { entries: PeDelayImportEntry[] };
  iat: PeIatDirectory;
  loadcfg: PeLoadConfig;
} => ({
  imports: createLinkedImports(),
  boundImports: createLinkedBoundImports(),
  delayImports: createLinkedDelayImports(),
  iat: createLinkedIatDirectory(),
  loadcfg: createLoadConfig(0)
});

export const createImportLinkingSections = () => [
  createWritableDataSection("", 0x2000, 0x400),
  // Microsoft Learn PE metadata calls ".didat" the canonical section name for protected delay-load IATs.
  createWritableDataSection(".didat", 0x2300, 0x600)
];

export const createImportLinkingMainSectionOnly = () => [
  createWritableDataSection("", 0x2000, 0x400)
];

export const createPeWithImportLinking = (): PeParseResult => {
  const pe = createBasePe();
  const { imports, boundImports, delayImports, iat, loadcfg } = createImportLinkingInputs();
  pe.sections = createImportLinkingSections();
  const importLinking = analyzeImportLinking(
    imports,
    boundImports,
    delayImports,
    iat,
    loadcfg,
    pe.sections
  );
  pe.imports = imports;
  pe.boundImports = boundImports;
  pe.delayImports = delayImports;
  pe.iat = iat;
  pe.loadcfg = loadcfg;
  pe.importLinking = importLinking as PeImportLinkingResult;
  return pe;
};
