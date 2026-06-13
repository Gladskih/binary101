"use strict";

export interface PeClrReadyToRunSection {
  type: number;
  name: string;
  rva: number;
  size: number;
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
