import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { test } from "node:test";
import { parsePeHeaders } from "../../analyzers/pe/core/index.js";
import { parseDebugDirectory } from "../../analyzers/pe/debug/directory.js";
import { MockFile } from "../helpers/mock-file.js";
import type { PortablePdbInfo } from "../../analyzers/pe/debug/portable-pdb-types.js";
import { parsePe } from "../../analyzers/pe/index.js";
import { PORTABLE_PDB_CUSTOM_KINDS } from "../../analyzers/pe/debug/portable-pdb-custom-kinds.js";
import type { PortablePdbConstant } from "../../analyzers/pe/debug/portable-pdb-constants.js";

interface DebugOracle {
  types: number[];
  kinds: string[];
  embedded: (Omit<PortablePdbInfo, "entryPoint" | "tables" | "locals"> & {
    tables: { name: string; rows: number }[];
    locals: { kind: string; name: string; slot?: number; attributes?: number; signatureSize?: number }[];
    constantValues: { name: string; constant: PortablePdbConstant }[];
  })[];
}

const referencePath = resolve("scan-results/pe-debug-reference/bin/Reference/debug/Reference.dll");
const oracle = JSON.parse(execFileSync("dotnet", [referencePath, referencePath], { encoding: "utf8" })) as DebugOracle;

const readDebug = async (path: string) => {
  const file = new MockFile(await readFile(path), path);
  const core = await parsePeHeaders(file);
  assert.ok(core);
  return parseDebugDirectory(file, core.dataDirs, core.rvaToOff, core.coff.Machine);
};

void test("compiler-produced embedded Portable PDB agrees with unchanged .NET reader", async () => {
  const parsed = await readDebug(referencePath);
  const pdb = parsed.entries.find(entry => entry.embeddedPortablePdb)?.embeddedPortablePdb?.portablePdb;

  assert.equal(parsed.warning, null);
  assert.deepEqual(parsed.entries.map(entry => entry.type), oracle.types);
  assert.ok(pdb);
  const expected = oracle.embedded[0]!;
  assert.deepEqual(pdb.id, expected.id);
  assert.deepEqual(pdb.documents, expected.documents);
  assert.deepEqual(pdb.locals.map(local => local.kind === "constant"
    ? { kind: local.kind, name: local.name, signatureSize: local.signatureSize } : local), expected.locals);
  assert.deepEqual(pdb.imports, expected.imports);
  assert.deepEqual(pdb.sequencePoints, expected.sequencePoints);
  assert.equal(pdb.methodsWithSequencePoints, expected.methodsWithSequencePoints);
  assert.deepEqual(pdb.customRecords.map(record => ({ ...record, data: record.data ?? null })), expected.customRecords);
  assert.deepEqual(pdb.tables.map(table => ({ name: table.name, rows: table.parsedRows })), expected.tables);
});

void test("Portable PDB custom kind GUIDs match the installed unchanged Roslyn catalogue", () => {
  assert.deepEqual(Object.keys(PORTABLE_PDB_CUSTOM_KINDS).sort(), oracle.kinds);
});

void test("Portable PDB constants resolve against same-image CLR metadata and agree with .NET", async () => {
  const parsed = await parsePe(new MockFile(await readFile(referencePath), referencePath));
  assert.ok(parsed && "debug" in parsed);
  const pdb = parsed.debug?.entries?.find(entry => entry.embeddedPortablePdb)?.embeddedPortablePdb?.portablePdb;

  assert.equal(parsed.debug?.warning, undefined);
  assert.ok(pdb);
  assert.deepEqual(pdb.locals.filter(local => local.kind === "constant")
    .map(local => ({ name: local.name, constant: local.constant })), oracle.embedded[0]!.constantValues);
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
