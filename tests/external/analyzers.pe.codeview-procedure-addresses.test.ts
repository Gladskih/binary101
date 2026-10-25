import assert from "node:assert/strict";
import { test } from "node:test";
import { execFileSync } from "node:child_process";
import { mkdir, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { MockFile } from "../helpers/mock-file.js";
import { parsePeHeaders } from "../../analyzers/pe/core/index.js";
import { readLegacyCodeViewSymbols } from "../../analyzers/pe/debug/legacy-codeview-symbols.js";
import { createCodeViewProcedureResolver } from "../../analyzers/pe/debug/codeview-procedure-addresses.js";
import { legacyReader } from "../fixtures/pe-legacy-codeview.js";
import type { PeLegacyCodeViewInfo } from "../../analyzers/pe/debug/legacy-codeview.js";

// Genuine linked CodeView symbol bytes from a native PDB are used as input to the
// same C7 record decoder. The NB09 data model below is a test envelope, not a claim
// that the linker emitted embedded NB09. No PDB parser is added to browser analysis.
void test("Linked CodeView procedure addresses agree with independently dumped DLL export RVAs", async () => {
  const root = resolve("scan-results/procedure-rva-native");
  await mkdir(root, { recursive: true });
  const object = resolve(root, "procedures.obj");
  const image = resolve(root, "procedures.dll");
  const pdb = resolve(root, "procedures.pdb");
  execFileSync("C:/Program Files/LLVM/bin/clang-cl.exe", ["/nologo", "/Z7", "/Od", "/GS-", "/c",
    resolve("tests/external/pe-debug-native/CodeViewProcedureAddresses.c"), `/Fo${object}`]);
  execFileSync("C:/Program Files/LLVM/bin/lld-link.exe", ["/dll", "/noentry", "/nodefaultlib", "/debug",
    "/incremental:no", `/out:${image}`, `/pdb:${pdb}`, object]);
  const oracle = execFileSync("C:/Program Files/LLVM/bin/llvm-pdbutil.exe",
    ["dump", "-modules", "-symbols", "-modi=0", pdb], { encoding: "utf8" });
  const stream = /debug stream: (\d+)/.exec(oracle);
  assert.ok(stream);
  const raw = resolve(root, "module.bin");
  execFileSync("C:/Program Files/LLVM/bin/llvm-pdbutil.exe", ["export", `--stream=${stream[1]}`, `--out=${raw}`, pdb]);
  const bytes = await readFile(raw);
  const warnings: string[] = [];
  const records = (await Promise.all([...oracle.matchAll(/^\s+(\d+) \| S_GPROC32 \[size = (\d+)\]/gm)]
    .map(match => readLegacyCodeViewSymbols(legacyReader(bytes, warnings), Number(match[1]),
      Number(match[1]) + Number(match[2]))))).flatMap(value => value.records);
  const core = await parsePeHeaders(new MockFile(await readFile(image)));
  assert.ok(core);
  const info: PeLegacyCodeViewInfo = { signature: "NB09", directories: [{ flags: 0, subsections: [] }] };
  const address = createCodeViewProcedureResolver(info, core.sections);
  const exports = execFileSync("C:/Program Files/LLVM/bin/llvm-readobj.exe", ["--coff-exports", image], { encoding: "utf8" });
  const expected = [...exports.matchAll(/Name: (Procedure\w+)\r?\n\s+RVA: 0x([\dA-Fa-f]+)/g)];

  assert.equal(expected.length, 2);
  assert.equal(records.length, 2);
  assert.deepEqual(records.map(record => ({ name: record.name, rva: address(0, record.procedure!).rva })),
    expected.map(match => ({ name: match[1], rva: Number.parseInt(match[2]!, 16) })));
  assert.deepEqual(warnings, []);
});
