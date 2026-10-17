import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { parseElf } from "../../analyzers/elf/index.js";
import { getElfSymbolDisplayName } from "../../analyzers/elf/symbol-names.js";
import { parsePe, isPeWindowsParseResult } from "../../analyzers/pe/index.js";
import { getPeExportDisplayName } from "../../analyzers/pe/directories/export-names.js";
import { parseCoffObject } from "../../analyzers/coff/index.js";
import { getCoffSymbolDisplayName } from "../../analyzers/coff/symbol-names.js";

const symbolNames = (path: string): string[] =>
  execFileSync("llvm-nm", ["--defined-only", "--extern-only", "-P", path], { encoding: "utf8" })
    .trim().split(/\r?\n/).map(line => line.split(/\s+/)[0]!)
    .filter(name => /^_{1,2}[RD]/.test(name));

const nativeNames = (language: string, names: string[]): string[] => {
  const canonical = names.map(name => name.startsWith("__") ? name.slice(1) : name);
  // Independently compiled, unmodified LLVM parsers from the package release gates.
  // See docs/symbol-demangling.md; never use the instrumented WASM as its own oracle.
  const output = execFileSync("wsl.exe", ["--exec",
    `${process.env["LLVM_DEMANGLER_ORACLE_ROOT"]}/llvm-${language}-demangle/.build/oracle`],
  { input: canonical.join("\n") + "\n", encoding: "utf8" });
  return output.trimEnd().split(/\r?\n/).map((text, index) =>
    text === "<invalid>" ? names[index]! : text);
};

const parsedNames = async (path: string, format: string): Promise<Map<string, string>> => {
  const file = new File([Uint8Array.from(await readFile(path))], path);
  if (format === "ELF") {
    const elf = await parseElf(file);
    assert.ok(elf?.symbolTables);
    return new Map(elf.symbolTables.flatMap(table => table.entries.map(symbol =>
      [symbol.name, getElfSymbolDisplayName(symbol)] as const)));
  }
  if (format === "PE") {
    const pe = await parsePe(file);
    assert.ok(pe && isPeWindowsParseResult(pe) && pe.exports);
    return new Map(pe.exports.entries.flatMap(entry => entry.names.map((name, index) =>
      [name, getPeExportDisplayName(entry.names, index)] as const)));
  }
  const coff = await parseCoffObject(file);
  assert.ok(coff?.coffDebug);
  return new Map(coff.coffDebug.symbols.map(symbol =>
    [symbol.name, getCoffSymbolDisplayName(symbol)] as const));
};

for (const [language, format, file, object, count] of [
  ["rust", "ELF", "rust_sample.elf.o", "rust_sample.o", 2],
  ["dlang", "ELF", "dlang_sample.linux.o", "dlang_sample.obj", 3],
  ["rust", "PE", "rust.dll", "rust_sample.o", 2],
  ["dlang", "PE", "dlang.dll", "dlang_sample.obj", 3],
  ["rust", "COFF", "rust_sample.o", "rust_sample.o", 2],
  ["dlang", "COFF", "dlang_sample.obj", "dlang_sample.obj", 3],
  ["rust", "COFF32", "rust_sample32.obj", "rust_sample32.obj", 2],
  ["dlang", "COFF32", "dlang_sample32.obj", "dlang_sample32.obj", 3]
] as const) {
  void test(`${language} compiler-produced ${format} matches unchanged LLVM`, {
    skip: !process.env["DEMANGLE_SAMPLES_DIR"] || !process.env["LLVM_DEMANGLER_ORACLE_ROOT"]
  }, async () => {
    const names = symbolNames(join(process.env["DEMANGLE_SAMPLES_DIR"]!, object));
    const expected = nativeNames(language, names);
    const actual = await parsedNames(join(process.env["DEMANGLE_SAMPLES_DIR"]!, file), format);

    assert.equal(names.length, count);
    assert.equal(expected.length, count);
    assert.deepEqual(names.map(name => actual.get(name)), expected);
  });
}
