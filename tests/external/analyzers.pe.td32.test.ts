import assert from "node:assert/strict";
import { test } from "node:test";
import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { createHash } from "node:crypto";
import { parseTd32 } from "../../analyzers/pe/debug/td32.js";
import { createExtraDebugPayloadSubject, identityRvaToOff } from "../fixtures/pe-debug-extra-payloads.js";

interface OracleSymbol { kind: string; name: string | null; compiler: string | null; }
interface OracleModule {
  name: string;
  segments: { segment: number; flags: number; offset: number; size: number }[];
  files: { name: string; segments: { segment: number; start: number; end: number;
    lines: { offset: number; line: number }[] }[] }[];
  symbols: OracleSymbol[];
}

// Real C++Builder FB0A, not a synthetic PE embedding. Downloaded unchanged from:
// https://github.com/AntonyFFC/arkanoid-game/blob/50d66b1b6306b3242f6f2f4cd71b9f75d3ac16e3/Project1.tds
// SHA256 d024920fe77881082fb17ba6ca245d9eeca6d0b00220fbcdef83684373fe88a0.
// Oracle.cs calls unchanged map2dbg/tds2pdb sources at
// 70cd89ff693cd622215309b0acb4326e530e7884. ParseTds covers names, modules,
// sources and symbols. TypStruct.Read is called separately for classes because
// their top-level type dispatch is disabled; the adapter initializes its empty
// reference slots but does not resolve or fabricate referenced type objects.
void test("real TD32 agrees with unchanged tds2pdb on every shared name, module and source line", async () => {
  const path = resolve("scan-results/td32-public/arkanoid-Project1.tds");
  const oracle = JSON.parse(execFileSync(resolve("scan-results/td32-oracle.exe"),
    [resolve("scan-results/td32-upstream.dll"), path], { encoding: "utf8", maxBuffer: 16 * 1024 * 1024 })) as {
      names: string[]; modules: OracleModule[]; globals: OracleSymbol[];
      classTypes: { index: number; name: string }[]; translatedNames: string[];
    };
  const bytes = await readFile(path);
  const subject = createExtraDebugPayloadSubject(bytes);
  const warnings: string[] = [];
  const parsed = await parseTd32(subject.file, subject.file.size, identityRvaToOff,
    0, subject.offset, subject.declaredSize, warning => warnings.push(warning));
  const sections = parsed!.directories[0]!.subsections;
  const names = sections.flatMap(section => section.data?.kind === "names" ? section.data.names : []);
  const modules = sections.flatMap(section => section.data?.kind === "module" ? [section.data] : []);
  const files = sections.flatMap(section => section.data?.kind === "source" ? section.data.files : []);

  assert.equal(parsed?.signature, "FB0A");
  assert.equal(createHash("sha256").update(bytes).digest("hex"),
    "d024920fe77881082fb17ba6ca245d9eeca6d0b00220fbcdef83684373fe88a0");
  assert.equal(names.length, 21093);
  assert.deepEqual(names, oracle.names);
  assert.equal(modules.length, 3);
  assert.deepEqual(modules.map(module => ({ name: names[module.nameIndex - 1], segments: module.segments })),
    oracle.modules.map(module => ({ name: module.name, segments: module.segments })));
  assert.deepEqual(files.map(file => ({ name: names[file.nameIndex - 1], segments: file.segments })),
    oracle.modules.flatMap(module => module.files));
  assert.equal(sections.flatMap(section => section.data?.kind === "symbols" ? section.data.records : []).length,
    oracle.globals.length + oracle.modules.reduce((count, module) => count + module.symbols.length, 0));
  assert.equal(sections.flatMap(section => section.data?.kind === "types" ? section.data.records : []).length, 28461);
  const classes = sections.flatMap(section => section.data?.kind === "types" ? section.data.records : [])
    .filter(record => record.type === 4 || record.type === 5);
  assert.equal(classes.length, 4322);
  assert.deepEqual(classes.map(record => ({ index: record.index,
    name: oracle.translatedNames[record.nameIndex! - 1] })),
  oracle.classTypes.map(({ index, name }) => ({ index, name })));
  assert.equal(warnings.length, 3);
  assert.equal(warnings.filter(warning => /layout is ambiguous/.test(warning)).length, 2);
  assert.ok(warnings.some(warning => /Pascal closure tails/.test(warning)));
});
