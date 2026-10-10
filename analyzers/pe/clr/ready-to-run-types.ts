"use strict";

import type { ReadyToRunDebugMethod } from "./ready-to-run-debug-types.js";

export interface PeClrReadyToRunSection {
  type: number;
  name: string;
  rva: number;
  size: number;
  decoded?: PeClrReadyToRunSectionData;
}

export interface PeClrReadyToRunMethod {
  methodRid: number;
  runtimeFunctionIndex: number;
  fixupOffset: number | null;
}

export interface PeClrReadyToRunInstanceMethod {
  signatureOffset: number;
  runtimeFunctionIndex: number;
  fixupOffset: number | null;
}

export interface PeClrReadyToRunImport {
  rva: number;
  size: number;
  flags: number;
  type: number;
  entrySize: number;
  signaturesRva: number;
  auxiliaryDataRva: number;
  entries: { value: Uint8Array; signatureRva: number | null }[];
}

export interface PeClrReadyToRunThunk {
  rva: number;
  size: number;
  kind: "eager" | "lazy" | "delay-load" | "tailcall" | "virtual-dispatch" | "delay-load family";
  helperCellRva: number | null;
  moduleCellRva?: number | null;
  importSectionIndex?: number;
}

export type PeClrReadyToRunSectionData =
  | { kind: "text"; text: string }
  | { kind: "debug-info"; methods: ReadyToRunDebugMethod[] }
  | { kind: "thunks"; entries: PeClrReadyToRunThunk[] }
  | { kind: "methods"; methods: PeClrReadyToRunMethod[] }
  | { kind: "instance-methods"; methods: PeClrReadyToRunInstanceMethod[] }
  | { kind: "imports"; imports: PeClrReadyToRunImport[] }
  | { kind: "hot-cold"; entries: { coldRuntimeFunction: number; hotRuntimeFunction: number }[] }
  | { kind: "components"; entries: PeClrReadyToRunComponent[] };

export interface PeClrReadyToRunCoreHeader {
  flags: number;
  sectionCount: number;
  sections: PeClrReadyToRunSection[];
}

export interface PeClrReadyToRunComponent {
  clrRva: number;
  clrSize: number;
  coreHeaderRva: number;
  coreHeaderSize: number;
  coreHeader?: PeClrReadyToRunCoreHeader;
}

// CoreCLR readytorun.h ReadyToRunSectionType values.
// https://github.com/dotnet/runtime/blob/main/src/coreclr/inc/readytorun.h
export const READY_TO_RUN_SECTION_RUNTIME_FUNCTIONS = 102;
export const READY_TO_RUN_SECTION_EXCEPTION_INFO = 104;

export interface PeClrReadyToRun {
  status: "ready-to-run" | "ngen" | "unknown-managed-native-header" | "truncated" | "unmapped" | "absent";
  signature: number | null;
  majorVersion: number | null;
  minorVersion: number | null;
  flags: number | null;
  sectionCount: number;
  sections: PeClrReadyToRunSection[];
  issues: string[];
}
