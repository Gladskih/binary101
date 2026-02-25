"use strict";

import { execFileSync } from "node:child_process";
import { parseReadelfDump, type ReadelfSnapshot } from "./elf-wsl-readelf-parser.js";

const MAX_BUFFER = 64 * 1024 * 1024;
const EXECUTABLE_DIRS = ["/bin", "/usr/bin", "/sbin", "/usr/sbin"];
const LIBRARY_DIRS = ["/lib", "/lib64", "/usr/lib", "/usr/lib64", "/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu"];
const PREFERRED_ELF_PATHS = [
  "/usr/bin/ls",
  "/usr/bin/cat",
  "/usr/bin/bash",
  "/usr/bin/env",
  "/usr/bin/find",
  "/usr/bin/grep",
  "/usr/bin/sed",
  "/usr/bin/awk"
];

export interface WslElfFixture {
  path: string;
  bytes: Uint8Array;
  readelf: ReadelfSnapshot;
}

export type {
  ReadelfHeaderInfo,
  ReadelfProgramHeaderInfo,
  ReadelfSectionInfo,
  ReadelfDynamicInfo,
  ReadelfDynSymbolsInfo,
  ReadelfSnapshot
} from "./elf-wsl-readelf-parser.js";

const quoteForBash = (value: string): string => `'${value.replace(/'/g, `'"'"'`)}'`;

const runWslText = (command: string): string =>
  String(execFileSync("wsl", ["bash", "-lc", command], { encoding: "utf8", maxBuffer: MAX_BUFFER }));

const runWslBytes = (command: string): Uint8Array =>
  new Uint8Array(execFileSync("wsl", ["bash", "-lc", command], { encoding: "buffer", maxBuffer: MAX_BUFFER }));

const buildFindCommand = (dirs: string[], expr: string, limit: number): string => {
  const allDirs = dirs.join(" ");
  return `find ${allDirs} -maxdepth 1 -type f ${expr} 2>/dev/null | sort | head -n ${limit}`;
};

const buildReadelfCommand = (path: string, includeDynSymbols: boolean): string => {
  const base = "--file-header --segments --sections --section-details --dynamic --notes --wide";
  const dyn = includeDynSymbols ? " --dyn-syms" : "";
  return `LC_ALL=C readelf ${base}${dyn} ${quoteForBash(path)} 2>/dev/null`;
};

const listCandidatePaths = (maxFiles: number): string[] => {
  const candidateLimit = Math.max(maxFiles * 8, 180);
  const executableCommand = buildFindCommand(EXECUTABLE_DIRS, "-perm /111", candidateLimit);
  const libraryCommand = buildFindCommand(LIBRARY_DIRS, "\\( -name '*.so' -o -name '*.so.*' \\)", candidateLimit);
  const output = runWslText(`${executableCommand}; ${libraryCommand}`);
  const seen = new Set<string>();
  const out: string[] = [];
  for (const path of PREFERRED_ELF_PATHS) {
    if (seen.has(path)) continue;
    seen.add(path);
    out.push(path);
  }
  for (const line of output.split(/\r?\n/)) {
    const path = line.trim();
    if (!path || seen.has(path)) continue;
    seen.add(path);
    out.push(path);
  }
  return out;
};

export function probeWslReadelf(): { available: boolean; reason: string } {
  try {
    runWslText("printf ready");
  } catch {
    return { available: false, reason: "WSL is not available from this shell." };
  }
  try {
    runWslText("command -v readelf >/dev/null 2>&1 && command -v cat >/dev/null 2>&1 && printf ready");
  } catch {
    return { available: false, reason: "WSL is available, but readelf or cat is missing." };
  }
  return { available: true, reason: "" };
}

export function collectWslElfFixtures(maxFiles: number, maxDynSymbolsFiles: number): WslElfFixture[] {
  const candidates = listCandidatePaths(maxFiles);
  const fixtures: WslElfFixture[] = [];
  let dynSymbolsBudget = Math.max(0, maxDynSymbolsFiles);
  for (const path of candidates) {
    if (fixtures.length >= maxFiles) break;
    const includeDynSymbols = dynSymbolsBudget > 0;
    let dump: string;
    try {
      dump = runWslText(buildReadelfCommand(path, includeDynSymbols));
    } catch {
      continue;
    }
    const readelf = parseReadelfDump(dump);
    if (!readelf) continue;
    let bytes: Uint8Array;
    try {
      bytes = runWslBytes(`cat -- ${quoteForBash(path)}`);
    } catch {
      continue;
    }
    fixtures.push({ path, bytes, readelf });
    if (includeDynSymbols && readelf.dynSymbols) dynSymbolsBudget -= 1;
  }
  return fixtures;
}
