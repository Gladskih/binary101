import assert from "node:assert/strict";
import { test } from "node:test";
import { readLegacyCodeViewModule, readLegacyCodeViewLibraries, readLegacyCodeViewSegmentNames,
  readLegacyCodeViewSegmentMap, readLegacyCodeViewFiles } from "../../../../../analyzers/pe/debug/legacy-codeview-modules.js";
import { legacyModule, legacyReader, legacyPascal, legacyU16, legacyU32 } from "../../../../fixtures/pe-legacy-codeview.js";

void test("legacy modules retain library references, style and segment contributions", async () => {
  const warnings: string[] = [];
  const bytes = legacyModule();
  bytes[10] = 1;
  const module = await readLegacyCodeViewModule(legacyReader(bytes, warnings));

  assert.deepEqual(module, { kind: "module", name: "module.obj", library: 1, overlay: 0,
    style: "CV", segments: [{ segment: 2, offset: 16, size: 8 }] });
  assert.match(warnings.join(" | "), /reserved field/);
  await assert.rejects(readLegacyCodeViewModule(legacyReader(bytes.slice(0, 19))), /segment array/);
  await assert.rejects(readLegacyCodeViewModule(legacyReader(bytes.slice(0, 22))), /bounds/);
});

void test("legacy library indices include the empty zeroth entry; segment names use NUL strings", async () => {
  const libraries = await readLegacyCodeViewLibraries(legacyReader([
    ...legacyPascal(""), ...legacyPascal("a.lib"), ...legacyPascal("b.lib")]));
  const names = await readLegacyCodeViewSegmentNames(legacyReader(new TextEncoder().encode(".text\0CODE\0")));

  assert.deepEqual(libraries, { kind: "libraries", names: ["", "a.lib", "b.lib"] });
  assert.deepEqual(names, { kind: "segmentNames", names: [{ offset: 0, name: ".text" }, { offset: 6, name: "CODE" }] });
  assert.deepEqual(await readLegacyCodeViewLibraries(legacyReader([])), { kind: "libraries", names: [] });
  await assert.rejects(readLegacyCodeViewLibraries(legacyReader([4, 65])), /bounds/);
  await assert.rejects(readLegacyCodeViewSegmentNames(legacyReader([65])), /NUL-terminated/);
});

const segmentMap = () => [...legacyU16(1), ...legacyU16(1), ...legacyU16(0x10f), ...legacyU16(2),
  ...legacyU16(3), ...legacyU16(4), ...legacyU16(0), ...legacyU16(6), ...legacyU32(16), ...legacyU32(24)];

void test("legacy segment map preserves logical count, names and access bits", async () => {
  const warnings: string[] = [];
  const bytes = segmentMap();
  bytes[2] = 2;
  const map = await readLegacyCodeViewSegmentMap(legacyReader(bytes, warnings));

  assert.deepEqual(map, { kind: "segmentMap", logicalCount: 2, segments: [{ flags: 0x10f, overlay: 2,
    group: 3, frame: 4, name: 0, className: 6, offset: 16, size: 24 }] });
  assert.match(warnings.join(" | "), /logical segment count/);
  await assert.rejects(readLegacyCodeViewSegmentMap(legacyReader(bytes.slice(0, -1))), /truncated/);
});

const fileIndex = () => [...legacyU16(2), ...legacyU16(2), ...legacyU16(0), ...legacyU16(1),
  ...legacyU16(1), ...legacyU16(1), ...legacyU32(0), ...legacyU32(0), ...legacyPascal("source.c")];

void test("legacy file index resolves shared names once without expanding module ranges", async () => {
  const files = await readLegacyCodeViewFiles(legacyReader(fileIndex()));

  assert.deepEqual(files, { kind: "files", names: ["source.c", "source.c"],
    modules: [{ first: 0, count: 1 }, { first: 1, count: 1 }] });
  assert.deepEqual(await readLegacyCodeViewFiles(legacyReader([0, 0, 0, 0])), { kind: "files", names: [], modules: [] });
  await assert.rejects(readLegacyCodeViewFiles(legacyReader(fileIndex().slice(0, 15))), /arrays are truncated/);
});

void test("legacy file index refuses invalid module references and out-of-range name offsets", async () => {
  const references = fileIndex();
  references[8] = 3;
  const names = fileIndex();
  names[12] = 255;

  await assert.rejects(readLegacyCodeViewFiles(legacyReader(references)), /references exceed/);
  await assert.rejects(readLegacyCodeViewFiles(legacyReader(names)), /bounds/);
});
