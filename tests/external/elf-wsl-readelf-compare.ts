"use strict";

import { DYNAMIC_FLAGS, DYNAMIC_FLAGS_1 } from "../../analyzers/elf/constants.js";
import type { ElfOptionEntry, ElfParseResult } from "../../analyzers/elf/types.js";
import type { ReadelfSnapshot } from "./elf-wsl-readelf-fixtures.js";

const ELF_TYPE_TO_TOKEN: Record<number, string> = {
  0: "NONE",
  1: "REL",
  2: "EXEC",
  3: "DYN",
  4: "CORE"
};

export interface ElfReadelfCoverage {
  header: number;
  programHeaders: number;
  sections: number;
  dynamic: number;
  dynSymbols: number;
  buildId: number;
  withNeeded: number;
  withFlags: number;
  withFlags1: number;
}

const asToken = (name: string | null, prefix: string): string | null => {
  if (!name) return null;
  if (name.startsWith(prefix)) return name.slice(prefix.length);
  if (name.startsWith("GNU_VER")) return name.replace(/^GNU_/, "");
  return name;
};

const normalizeName = (value: string): string => value.replace(/@{1,2}.*/, "");

const setEquals = (left: Set<string>, right: Set<string>): boolean => {
  if (left.size !== right.size) return false;
  for (const value of left) if (!right.has(value)) return false;
  return true;
};

const firstDifference = (left: Set<string>, right: Set<string>): string | null => {
  for (const value of left) if (!right.has(value)) return `missing "${value}"`;
  for (const value of right) if (!left.has(value)) return `unexpected "${value}"`;
  return null;
};

const normalizeDynamicFlagName = (name: string, prefix: string): string => {
  if (name.startsWith(prefix)) return name.slice(prefix.length);
  return name;
};

const knownDynamicTokens = (flags: ElfOptionEntry[], prefix: string): Set<string> =>
  new Set(flags.map(([, name]) => normalizeDynamicFlagName(name, prefix)));

const decodeDynamicTokens = (
  value: number | null | undefined,
  flags: ElfOptionEntry[],
  prefix: string
): Set<string> => {
  if (value == null) return new Set<string>();
  const normalized = value >>> 0;
  const out = new Set<string>();
  for (const [bit, name] of flags) {
    if ((normalized & (bit >>> 0)) !== 0) out.add(normalizeDynamicFlagName(name, prefix));
  }
  return out;
};

const readBuildId = (elf: ElfParseResult): string | null => {
  const note = elf.notes?.entries.find(entry => entry.typeName === "NT_GNU_BUILD_ID" && typeof entry.value === "string");
  return note?.value?.toLowerCase() || null;
};

const compareArrayField = (
  issues: string[],
  label: string,
  actual: { vaddr: bigint; size: bigint } | null | undefined,
  expected: { vaddr: bigint; size: bigint } | null
): void => {
  if (!actual && !expected) return;
  if (!actual || !expected) {
    issues.push(`${label}: presence mismatch`);
    return;
  }
  if (actual.vaddr !== expected.vaddr || actual.size !== expected.size) {
    issues.push(`${label}: expected (${expected.vaddr}, ${expected.size}), got (${actual.vaddr}, ${actual.size})`);
  }
};

export function compareElfWithReadelf(
  elf: ElfParseResult,
  readelf: ReadelfSnapshot,
  coverage: ElfReadelfCoverage
): string[] {
  const issues: string[] = [];

  coverage.header += 1;
  const header = readelf.header;
  const expectedClass = elf.is64 ? "ELF64" : "ELF32";
  if (expectedClass !== header.className) issues.push(`header.class expected ${header.className}, got ${expectedClass}`);
  if (elf.littleEndian !== header.littleEndian) issues.push("header.endianness mismatch");
  const expectedType = ELF_TYPE_TO_TOKEN[elf.header.type] || `TYPE_${elf.header.type}`;
  if (expectedType !== header.typeToken) issues.push(`header.type expected ${header.typeToken}, got ${expectedType}`);
  if (elf.header.entry !== header.entry) issues.push("header.entry mismatch");
  if (elf.header.phoff !== BigInt(header.phoff)) issues.push("header.phoff mismatch");
  if (elf.header.shoff !== BigInt(header.shoff)) issues.push("header.shoff mismatch");
  if (elf.header.flags !== header.flags) issues.push("header.flags mismatch");
  if (elf.header.ehsize !== header.ehsize) issues.push("header.ehsize mismatch");
  if (elf.header.phentsize !== header.phentsize) issues.push("header.phentsize mismatch");
  if (elf.header.phnum !== header.phnum) issues.push("header.phnum mismatch");
  if (elf.header.shentsize !== header.shentsize) issues.push("header.shentsize mismatch");
  if (elf.header.shnum !== header.shnum) issues.push("header.shnum mismatch");
  if (elf.header.shstrndx !== header.shstrndx) issues.push("header.shstrndx mismatch");

  coverage.programHeaders += 1;
  if (elf.programHeaders.length !== readelf.programHeaders.length) {
    issues.push(`program header count expected ${readelf.programHeaders.length}, got ${elf.programHeaders.length}`);
  }
  const phCount = Math.min(elf.programHeaders.length, readelf.programHeaders.length);
  for (let index = 0; index < phCount; index += 1) {
    const actual = elf.programHeaders[index];
    const expected = readelf.programHeaders[index];
    if (!actual || !expected) continue;
    const token = asToken(actual.typeName, "PT_");
    if (token && token !== expected.type) issues.push(`program[${index}].type expected ${expected.type}, got ${token}`);
    if (actual.offset !== expected.offset) issues.push(`program[${index}].offset mismatch`);
    if (actual.vaddr !== expected.vaddr) issues.push(`program[${index}].vaddr mismatch`);
    if (actual.paddr !== expected.paddr) issues.push(`program[${index}].paddr mismatch`);
    if (actual.filesz !== expected.filesz) issues.push(`program[${index}].filesz mismatch`);
    if (actual.memsz !== expected.memsz) issues.push(`program[${index}].memsz mismatch`);
    if ((actual.flags & 0x7) !== expected.flagsMask) issues.push(`program[${index}].flags mismatch`);
    if (actual.align !== expected.align) issues.push(`program[${index}].align mismatch`);
  }

  coverage.sections += 1;
  if (elf.sections.length !== readelf.sections.length) {
    issues.push(`section count expected ${readelf.sections.length}, got ${elf.sections.length}`);
  }
  const sectionCount = Math.min(elf.sections.length, readelf.sections.length);
  for (let index = 0; index < sectionCount; index += 1) {
    const actual = elf.sections[index];
    const expected = readelf.sections[index];
    if (!actual || !expected) continue;
    if (actual.index !== expected.index) issues.push(`section[${index}].index mismatch`);
    if ((actual.name || "") !== expected.name) issues.push(`section[${index}].name mismatch`);
    const typeToken = asToken(actual.typeName, "SHT_");
    if (typeToken && typeToken !== expected.type) {
      issues.push(`section[${index}].type expected ${expected.type}, got ${typeToken}`);
    }
    if (actual.addr !== expected.addr) issues.push(`section[${index}].addr mismatch`);
    if (actual.offset !== expected.off) issues.push(`section[${index}].offset mismatch`);
    if (actual.size !== expected.size) issues.push(`section[${index}].size mismatch`);
    if (actual.entsize !== expected.entsize) issues.push(`section[${index}].entsize mismatch`);
    if (actual.link !== expected.link) issues.push(`section[${index}].link mismatch`);
    if (actual.info !== expected.info) issues.push(`section[${index}].info mismatch`);
    if (actual.addralign !== BigInt(expected.align)) issues.push(`section[${index}].addralign mismatch`);
    if (actual.flags !== expected.flagsMask) issues.push(`section[${index}].flags mismatch`);
  }

  if (readelf.dynamic) {
    coverage.dynamic += 1;
    const actual = elf.dynamic;
    if (!actual) {
      issues.push("dynamic: expected section, but parser returned null");
    } else {
      const expected = readelf.dynamic;
      if (expected.needed.length) coverage.withNeeded += 1;
      const actualNeeded = [...actual.needed].sort().join("|");
      const expectedNeeded = [...expected.needed].sort().join("|");
      if (actualNeeded !== expectedNeeded) issues.push("dynamic.needed mismatch");
      if ((actual.soname || null) !== expected.soname) issues.push("dynamic.soname mismatch");
      if ((actual.rpath || null) !== expected.rpath) issues.push("dynamic.rpath mismatch");
      if ((actual.runpath || null) !== expected.runpath) issues.push("dynamic.runpath mismatch");
      if ((actual.init || null) !== expected.init) issues.push("dynamic.init mismatch");
      if ((actual.fini || null) !== expected.fini) issues.push("dynamic.fini mismatch");
      compareArrayField(issues, "dynamic.preinitArray", actual.preinitArray, expected.preinitArray);
      compareArrayField(issues, "dynamic.initArray", actual.initArray, expected.initArray);
      compareArrayField(issues, "dynamic.finiArray", actual.finiArray, expected.finiArray);

      const dtFlagsKnown = knownDynamicTokens(DYNAMIC_FLAGS, "DF_");
      const dtFlagsExpected = new Set([...expected.flags].filter(token => dtFlagsKnown.has(token)));
      const dtFlagsActual = decodeDynamicTokens(actual.flags, DYNAMIC_FLAGS, "DF_");
      if (!setEquals(dtFlagsActual, dtFlagsExpected)) {
        issues.push(`dynamic.flags mismatch: ${firstDifference(dtFlagsActual, dtFlagsExpected) || "different sets"}`);
      }
      if (expected.flags.size || actual.flags != null) coverage.withFlags += 1;

      const dtFlags1Known = knownDynamicTokens(DYNAMIC_FLAGS_1, "DF_1_");
      const dtFlags1Expected = new Set([...expected.flags1].filter(token => dtFlags1Known.has(token)));
      const dtFlags1Actual = decodeDynamicTokens(actual.flags1, DYNAMIC_FLAGS_1, "DF_1_");
      if (!setEquals(dtFlags1Actual, dtFlags1Expected)) {
        issues.push(`dynamic.flags1 mismatch: ${firstDifference(dtFlags1Actual, dtFlags1Expected) || "different sets"}`);
      }
      if (expected.flags1.size || actual.flags1 != null) coverage.withFlags1 += 1;
    }
  }

  if (readelf.dynSymbols) {
    coverage.dynSymbols += 1;
    if (!elf.dynSymbols) {
      issues.push("dynSymbols: expected values, but parser returned null");
    } else {
      const actualImports = new Set(elf.dynSymbols.importSymbols.map(symbol => normalizeName(symbol.name)));
      const expectedImports = new Set(readelf.dynSymbols.imports);
      if (!setEquals(actualImports, expectedImports)) {
        issues.push(`dynSymbols.imports mismatch: ${firstDifference(actualImports, expectedImports) || "different sets"}`);
      }
      const actualExports = new Set(elf.dynSymbols.exportSymbols.map(symbol => normalizeName(symbol.name)));
      const expectedExports = new Set(readelf.dynSymbols.exports);
      if (!setEquals(actualExports, expectedExports)) {
        issues.push(`dynSymbols.exports mismatch: ${firstDifference(actualExports, expectedExports) || "different sets"}`);
      }
    }
  }

  if (readelf.buildId) {
    coverage.buildId += 1;
    const actualBuildId = readBuildId(elf);
    if (actualBuildId !== readelf.buildId) {
      issues.push(`notes.build-id expected ${readelf.buildId}, got ${actualBuildId || "(none)"}`);
    }
  }

  return issues;
}
