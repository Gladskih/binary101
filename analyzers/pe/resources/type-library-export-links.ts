"use strict";

import type { PeExportEntry, parseExportDirectory } from "../directories/exports.js";
import type { PeResources } from "./index.js";

type ExportDirectory = Pick<NonNullable<Awaited<ReturnType<typeof parseExportDirectory>>>,
  "dllName" | "NumberOfFunctions" | "issues" | "entries">;

export interface TypeLibraryExportMatch {
  ordinal: number;
  library: string;
  module: string;
  function: string;
  entry: string | number;
}

export interface TypeLibraryExportAnalysis {
  matches: TypeLibraryExportMatch[];
  warnings: string[];
}

const basename = (value: string): string => value.split(/[\\/]/u).at(-1)?.toLowerCase() ?? "";
const completeExports = (exports: ExportDirectory): boolean =>
  exports.entries.length === exports.NumberOfFunctions &&
  !exports.issues.some(issue => /truncat|missing|does not map/iu.test(issue));

const indexExports = (entries: PeExportEntry[]): {
  byOrdinal: Map<number, PeExportEntry>; byName: Map<string, PeExportEntry>
} => {
  const byOrdinal = new Map<number, PeExportEntry>();
  const byName = new Map<string, PeExportEntry>();
  for (const entry of entries) {
    byOrdinal.set(entry.ordinal, entry);
    for (const name of entry.names) byName.set(name, entry);
  }
  return { byOrdinal, byName };
};

export const analyzeTypeLibraryExports = (
  resources: PeResources | null, exports: ExportDirectory | null
): TypeLibraryExportAnalysis => {
  const result: TypeLibraryExportAnalysis = { matches: [], warnings: [] };
  if (!resources || !exports?.dllName) return result;
  const exportName = basename(exports.dllName);
  const { byOrdinal, byName } = indexExports(exports.entries);
  const seen = new Set<string>();
  for (const group of resources.detail) {
    if (group.typeName !== "TYPELIB") continue;
    for (const resource of group.entries) for (const lang of resource.langs) {
      const analysis = lang.typeLibrary?.analysis;
      if (!analysis) continue;
      for (const type of analysis.types) {
        // TKIND_MODULE uses [dllname] and [entry] for exported DLL functions.
        // https://learn.microsoft.com/en-us/windows/win32/api/oaidl/nf-oaidl-itypeinfo-getdllentry
        if (type.kind !== 2 || !type.dll || basename(type.dll) !== exportName) continue;
        for (const member of type.functions) {
          if (member.entry === null || member.entry === "") continue;
          const entry = typeof member.entry === "number"
            ? byOrdinal.get(member.entry) : byName.get(member.entry);
          const library = analysis.name ?? resource.name ?? String(resource.id ?? "?");
          const key = JSON.stringify([library, type.name, member.name, member.entry]);
          if (seen.has(key)) continue;
          seen.add(key);
          if (entry) {
            result.matches.push({ ordinal: entry.ordinal, library,
              module: type.name ?? "?", function: member.name ?? "?", entry: member.entry });
          } else if (completeExports(exports)) {
            result.warnings.push(`TYPELIB ${library} module ${type.name ?? "?"} function ` +
              `${member.name ?? "?"} declares DLL entry ${member.entry}, but ${exports.dllName} ` +
              `has no matching export.`);
          }
        }
      }
    }
  }
  return result;
};
