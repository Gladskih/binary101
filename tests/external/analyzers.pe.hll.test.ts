import assert from "node:assert/strict";
import { test } from "node:test";
import { execFileSync } from "node:child_process";
import { readFile, mkdtemp, rm, writeFile } from "node:fs/promises";
import { resolve, join } from "node:path";
import { tmpdir } from "node:os";
import { MockFile } from "../helpers/mock-file.js";
import { parsePe, isPeWindowsParseResult } from "../../analyzers/pe/index.js";
import { createPeCodeViewOverlay } from "../fixtures/pe-codeview-locations.js";
import { createHllInspection } from "../fixtures/pe-hll.js";
import { createLegacyCodeView, legacyModule } from "../fixtures/pe-legacy-codeview.js";
import { createPeWithDebugPayloads } from "../fixtures/pe-debug-file.js";

// Official Open Watcom 2026-10-23 build, unchanged compiler/linker/wdump.
// Tag commit: 065b3083b9f06919c871c67ce608e3b29674ffce.
// NB04 module/public readers in wdump are independent; its local/type dump paths
// assume HLL record bodies and cannot validate the C7 streams in this PE fixture.
void test("Open Watcom NB04 overlay reaches the PE result with native module/public names and C7 content", async () => {
  const path = resolve("scan-results/pe-debug-native/HllSample.exe");
  const bytes = await readFile(path);
  const pe = await parsePe(new MockFile(bytes, "HllSample.exe"));
  assert.ok(pe && isPeWindowsParseResult(pe));
  const sources = pe.debug?.codeViewSources;
  assert.equal(sources?.length, 1);
  assert.equal(sources[0]!.kind, "overlay");
  assert.equal(sources[0]!.legacyCodeView.signature, "NB04");
  assert.equal(pe.debug?.warning, undefined);
  const oracle = execFileSync(resolve("scan-results/open-watcom/binnt64/wdump.exe"), ["-d", "-Dmg", path],
    { timeout: 5000, maxBuffer: 1024 * 1024 }).toString();
  const data = sources[0]!.legacyCodeView.directories[0]!.subsections.map(section => section.data);
  const modules = data.flatMap(value => value?.kind === "module" ? [value.name] : []);
  const publics = data.flatMap(value => value?.kind === "publics" ? value.names : []);
  assert.equal(modules.length, 2);
  assert.equal(publics.length, 2);
  assert.ok(modules.every(name => oracle.includes(name)));
  assert.ok(publics.every(name => oracle.includes(name)));
  assert.ok(publics.includes("_entry"));
  const symbols = data.flatMap(value => value?.kind === "symbols" ? value.records : []);
  const types = data.flatMap(value => value?.kind === "types" ? value.records : []);
  assert.ok(symbols.some(record => record.name === "state"));
  assert.ok(types.some(record => record.name === "PublicState"));
  assert.ok(types.some(record => record.members?.some(member => member.name === "count")));
  assert.deepEqual(pe.debug?.rawDataRanges, [{ start: sources[0]!.offset, end: bytes.length }]);
});

void test("Controlled HLL automatic-variable records agree with the unchanged Open Watcom decoder", async () => {
  const file = createPeCodeViewOverlay(createHllInspection());
  const pe = await parsePe(file);
  assert.ok(pe && isPeWindowsParseResult(pe));
  const records = pe.debug!.codeViewSources![0]!.legacyCodeView.directories[0]!.subsections
    .flatMap(section => section.data?.kind === "symbols" ? section.data.records : []);
  const temporary = await mkdtemp(join(tmpdir(), "binary101-hll-"));
  try {
    const path = join(temporary, "controlled-hll.exe");
    await writeFile(path, file.data);
    const oracle = execFileSync(resolve("scan-results/open-watcom/binnt64/wdump.exe"), ["-d", "-Dm", path],
      { timeout: 5000, maxBuffer: 1024 * 1024 }).toString();
    const names = [...oracle.matchAll(/^ {6}name: "([^"]*)"/gm)].map(match => match[1]!);
    assert.equal(names.length, 101);
    assert.deepEqual(records.map(record => record.name), names);
  } finally { await rm(temporary, { recursive: true, force: true }); }
});

void test("Open Watcom C7 stream bytes in NB04 agree with unchanged Microsoft record readers", async () => {
  const bytes = await readFile(resolve("scan-results/pe-debug-native/HllSample.exe"));
  const pe = await parsePe(new MockFile(bytes));
  assert.ok(pe && isPeWindowsParseResult(pe));
  const source = pe.debug!.codeViewSources![0]!;
  const sections = source.legacyCodeView.directories[0]!.subsections;
  const records = sections.flatMap(section => section.data?.kind === "types" ? section.data.records : []);
  const names = records.flatMap(record => [record.name, ...(record.members ?? []).map(member => member.name)])
    .filter((name): name is string => name !== undefined && name.length > 0);
  // Translate only the container: old NB04 directory/module -> NB05 directory/module.
  // Both C7 subsection payloads remain byte-for-byte the compiler output.
  const payload = createLegacyCodeView([
    { type: 0x120, module: 1, data: legacyModule("HllSample.obj") },
    ...sections.filter(section => section.type === 0x103 || section.type === 0x104).map(section => ({
      type: section.type === 0x103 ? 0x121 : 0x124, module: section.module,
      data: bytes.subarray(source.offset + section.offset, source.offset + section.offset + section.size)
    }))
  ], "NB05");
  const temporary = await mkdtemp(join(tmpdir(), "binary101-hll-c7-"));
  try {
    const path = join(temporary, "controlled-c7-envelope.exe");
    await writeFile(path, createPeWithDebugPayloads([{ type: 2, data: payload }]).data);
    const oracle = execFileSync(resolve("scan-results/pe-debug-native/cvdump.exe"), ["-s", "-t", path],
      { timeout: 5000, maxBuffer: 1024 * 1024 }).toString();
    assert.ok(names.includes("PublicState"));
    assert.ok(names.includes("count"));
    assert.ok(names.every(name => oracle.includes(name)));
  } finally { await rm(temporary, { recursive: true, force: true }); }
});
