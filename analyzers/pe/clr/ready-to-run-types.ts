"use strict";

export interface PeClrReadyToRunSection {
  type: number;
  name: string;
  rva: number;
  size: number;
}

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
