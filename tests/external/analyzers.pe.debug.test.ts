import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { test } from "node:test";
import { parsePeHeaders } from "../../analyzers/pe/core/index.js";
import { parseDebugDirectory } from "../../analyzers/pe/debug/directory.js";
import { MockFile } from "../helpers/mock-file.js";
import type { PortablePdbInfo } from "../../analyzers/pe/debug/portable-pdb-types.js";

const readDebug = async (path: string) => {
  const file = new MockFile(await readFile(path), path);
  const core = await parsePeHeaders(file);
  assert.ok(core);
  return parseDebugDirectory(file, core.dataDirs, core.rvaToOff, core.coff.Machine);
};

void test("compiler-produced embedded Portable PDB agrees with unchanged .NET reader", async () => {
  const path = resolve("scan-results/pe-debug-reference/bin/Reference/debug/Reference.dll");
  const oracle = JSON.parse(execFileSync("dotnet", [path, path], { encoding: "utf8" })) as {
    types: number[]; embedded: (Omit<PortablePdbInfo, "entryPoint" | "tables"> & {
      tables: { name: string; rows: number }[]
    })[]
  };
  const parsed = await readDebug(path);
  const pdb = parsed.entries.find(entry => entry.embeddedPortablePdb)?.embeddedPortablePdb?.portablePdb;

  assert.equal(parsed.warning, null);
  assert.deepEqual(parsed.entries.map(entry => entry.type), oracle.types);
  assert.ok(pdb);
  const expected = oracle.embedded[0]!;
  assert.deepEqual(pdb.id, expected.id);
  assert.deepEqual(pdb.documents, expected.documents);
  assert.deepEqual(pdb.locals, expected.locals);
  assert.deepEqual(pdb.sequencePoints, expected.sequencePoints);
  assert.equal(pdb.methodsWithSequencePoints, expected.methodsWithSequencePoints);
  assert.deepEqual(pdb.customRecords, expected.customRecords);
  assert.deepEqual(pdb.tables.map(table => ({ name: table.name, rows: table.parsedRows })), expected.tables);
});

void test("Windows system PE debug directories agree with LLVM", { skip: process.platform !== "win32" }, async () => {
  const path = resolve(process.env["SystemRoot"]!, "System32", "kernel32.dll");
  const output = execFileSync(process.env["LLVM_READOBJ"] ?? "llvm-readobj",
    ["--coff-debug-directory", path], { encoding: "utf8", maxBuffer: 1024 * 1024 });
  const parsed = await readDebug(path);
  const oracleTypes = [...output.matchAll(/Type: [^\n]*\(0x([0-9A-F]+)\)/g)]
    .map(match => Number.parseInt(match[1]!, 16));

  assert.ok(oracleTypes.length > 0);
  assert.deepEqual(parsed.entries.map(entry => entry.type), oracleTypes);
  assert.equal(parsed.entry?.path, /PDBFileName: ([^\r\n]+)/.exec(output)?.[1]);
  assert.equal(parsed.entry?.age, Number(/PDBAge: (\d+)/.exec(output)?.[1]));
  assert.equal(parsed.warning, null);
});
