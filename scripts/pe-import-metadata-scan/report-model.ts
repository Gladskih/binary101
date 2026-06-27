"use strict";

import type { PeImportMetadataEntry } from "../../pe-import-metadata-schema.js";

export type CountRecord = { key: string; count: number };
export type DllImpactRecord = { dll: string; importCount: number; fileCount: number; family?: string };
export type ErrorRecord = { path: string; message: string };
export type ImportedFunction = { dll: string; name: string | null; metadata: PeImportMetadataEntry | null };

type DllAccumulator = { importCount: number; files: Set<string>; family: string | null };

export type ScanOptions = {
  roots: string[];
  outputPath: string;
  maxPeFiles: number | null;
  maxEntrypoints: number;
};

export type ScanState = {
  filesVisited: number;
  mzCandidates: number;
  peFiles: number;
  x86PeFiles: number;
  x86EntrypointsAnalyzed: number;
  x86EntrypointsWithImportReturns: number;
  importFunctions: number;
  namedImportFunctions: number;
  metadataMatched: number;
  cleanupCandidates: number;
  cleanupComplete: number;
  cleanupUnknownSize: number;
  metadataMatchesBySource: Map<string, number>;
  missingMetadataByDll: Map<string, DllAccumulator>;
  unknownStackSizeByFunction: Map<string, number>;
  entrypointIssues: Map<string, number>;
  errors: ErrorRecord[];
};

export type ScanReport = {
  generatedAt: string;
  roots: string[];
  maxPeFiles: number | null;
  maxEntrypoints: number;
  totals: Omit<ScanState, "metadataMatchesBySource" | "missingMetadataByDll" |
    "unknownStackSizeByFunction" | "entrypointIssues" | "errors">;
  metadataMatchesBySource: CountRecord[];
  missingMetadataByDll: DllImpactRecord[];
  missingMetadataByFamily: DllImpactRecord[];
  unknownStackSizeByFunction: CountRecord[];
  entrypointIssues: CountRecord[];
  errors: ErrorRecord[];
};

export const initialState = (): ScanState => ({
  filesVisited: 0,
  mzCandidates: 0,
  peFiles: 0,
  x86PeFiles: 0,
  x86EntrypointsAnalyzed: 0,
  x86EntrypointsWithImportReturns: 0,
  importFunctions: 0,
  namedImportFunctions: 0,
  metadataMatched: 0,
  cleanupCandidates: 0,
  cleanupComplete: 0,
  cleanupUnknownSize: 0,
  metadataMatchesBySource: new Map(),
  missingMetadataByDll: new Map(),
  unknownStackSizeByFunction: new Map(),
  entrypointIssues: new Map(),
  errors: []
});

export const increment = (counts: Map<string, number>, key: string, amount = 1): void => {
  counts.set(key, (counts.get(key) ?? 0) + amount);
};

const classifyDll = (dllKey: string): string | null => {
  if (/^(msvcr|vcruntime|ucrtbase|api-ms-win-crt-)/u.test(dllKey)) return "MSVC C runtime";
  if (/^(msvcp|concrt)/u.test(dllKey)) return "MSVC C++ runtime";
  if (/^(qt[56]|libqt)/u.test(dllKey)) return "Qt";
  if (/^(gtk|gdk|glib|gobject|gio|cairo|pango|atk|harfbuzz)/u.test(dllKey)) return "GTK stack";
  return dllKey.includes("boost") ? "Boost" : null;
};

export const addDllImpact = (
  impacts: Map<string, DllAccumulator>,
  key: string,
  path: string,
  amount = 1,
  family: string | null = classifyDll(key)
): void => {
  const current = impacts.get(key) ?? { importCount: 0, files: new Set<string>(), family };
  current.importCount += amount;
  current.files.add(path);
  impacts.set(key, current);
};

const familyImpactRecords = (missingMetadataByDll: ReadonlyMap<string, DllAccumulator>): DllImpactRecord[] => {
  const byFamily = new Map<string, DllAccumulator>();
  for (const [dll, impact] of missingMetadataByDll) {
    if (!impact.family) continue;
    for (const path of impact.files) addDllImpact(byFamily, impact.family, path, 0, null);
    const family = byFamily.get(impact.family);
    if (family) family.importCount += impact.importCount;
    if (family) byFamily.set(impact.family, family);
    if (!family) addDllImpact(byFamily, impact.family, dll, impact.importCount, null);
  }
  return dllImpactRecords(byFamily);
};

const countRecords = (counts: ReadonlyMap<string, number>): CountRecord[] =>
  [...counts.entries()]
    .map(([key, count]) => ({ key, count }))
    .sort((left, right) => right.count - left.count || left.key.localeCompare(right.key));

const dllImpactRecords = (impacts: ReadonlyMap<string, DllAccumulator>): DllImpactRecord[] =>
  [...impacts.entries()]
    .map(([dll, impact]) => ({
      dll,
      importCount: impact.importCount,
      fileCount: impact.files.size,
      ...(impact.family ? { family: impact.family } : {})
    }))
    .sort((left, right) => right.fileCount - left.fileCount || right.importCount - left.importCount);

export const cleanErrorMessage = (error: unknown): string => {
  const message = error instanceof Error ? error.message : String(error);
  return message.length > 500 ? `${message.slice(0, 500)}...` : message;
};

export const buildReport = (options: ScanOptions, state: ScanState): ScanReport => {
  return {
    generatedAt: new Date().toISOString(),
    roots: options.roots,
    maxPeFiles: options.maxPeFiles,
    maxEntrypoints: options.maxEntrypoints,
    totals: {
      filesVisited: state.filesVisited,
      mzCandidates: state.mzCandidates,
      peFiles: state.peFiles,
      x86PeFiles: state.x86PeFiles,
      x86EntrypointsAnalyzed: state.x86EntrypointsAnalyzed,
      x86EntrypointsWithImportReturns: state.x86EntrypointsWithImportReturns,
      importFunctions: state.importFunctions,
      namedImportFunctions: state.namedImportFunctions,
      metadataMatched: state.metadataMatched,
      cleanupCandidates: state.cleanupCandidates,
      cleanupComplete: state.cleanupComplete,
      cleanupUnknownSize: state.cleanupUnknownSize
    },
    metadataMatchesBySource: countRecords(state.metadataMatchesBySource),
    missingMetadataByDll: dllImpactRecords(state.missingMetadataByDll),
    missingMetadataByFamily: familyImpactRecords(state.missingMetadataByDll),
    unknownStackSizeByFunction: countRecords(state.unknownStackSizeByFunction),
    entrypointIssues: countRecords(state.entrypointIssues),
    errors: state.errors
  };
};
