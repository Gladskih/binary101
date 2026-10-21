import assert from "node:assert/strict";
import { test } from "node:test";
import { parseTd32Sources } from "../../../../../analyzers/pe/debug/td32-sources.js";
import { createTd32 } from "../../../../fixtures/pe-td32.js";
import { MockFile } from "../../../../helpers/mock-file.js";
import { inlinePeSectionName } from "../../../../../analyzers/pe/sections/name.js";
import { createDebugViewEntry } from "../../../../fixtures/pe-debug-view-subject.js";
import { createTd32Info } from "../../../../fixtures/pe-td32-view.js";
import { createPeTd32Overlay, createPeTd32Section } from "../../../../fixtures/pe-td32-locations.js";
import { parsePe, isPeWindowsParseResult } from "../../../../../analyzers/pe/index.js";

const section = (offset: number, size: number) => ({ name: inlinePeSectionName(".debug"),
  virtualAddress: 0x1000, virtualSize: size, pointerToRawData: offset, sizeOfRawData: size,
  characteristics: 0 });
const file = () => new MockFile(Uint8Array.from([...new Uint8Array(32), ...createTd32([])]));

for (const create of [createPeTd32Overlay, createPeTd32Section]) {
  void test(`TD32 source reaches the full PE result and explains its physical bytes: ${create.name}`, async () => {
    const source = create();
    const pe = await parsePe(source);
    assert.ok(pe && isPeWindowsParseResult(pe));
    const found = pe.debug?.td32Sources;

    assert.equal(found?.length, 1);
    assert.equal(found?.[0]?.td32.signature, "FB09");
    assert.deepEqual(pe.debug?.rawDataRanges, [{ start: found![0]!.offset, end: source.size }]);
    assert.equal(pe.debug?.entries, undefined);
    assert.equal(pe.debug?.warning, undefined);
  });
}

void test("TD32 discovers an appended container without inventing a debug directory entry", async () => {
  const source = file();
  const warnings: string[] = [];
  const parsed = await parseTd32Sources(source, [], 32, [], () => null, message => warnings.push(message));

  assert.deepEqual(parsed.map(value => ({ ...value, td32: value.td32.signature })),
    [{ kind: "overlay", offset: 32, size: source.size - 32, td32: "FB09" }]);
  assert.deepEqual(warnings, []);
});

void test("TD32 discovers a .debug container and does not decode it again through the EOF anchor", async () => {
  const source = file();
  const warnings: string[] = [];
  const parsed = await parseTd32Sources(source, [section(32, source.size - 32)],
    16, [], () => null, message => warnings.push(message));

  assert.equal(parsed.length, 1);
  assert.equal(parsed[0]?.kind, "section");
  assert.deepEqual(warnings, []);
});

for (const pointer of [0, 32]) {
  void test(`TD32 avoids reparsing a container already decoded through a directory entry at ${pointer}`, async () => {
    const source = file();
    const entry = { ...createDebugViewEntry(0, 0x1000, pointer, source.size - 32),
      pointerToRawData: pointer, td32: createTd32Info() };
    const warnings: string[] = [];
    const parsed = await parseTd32Sources(source, [section(32, source.size - 32)], 32,
      [entry], rva => rva >= 0x1000 && rva < 0x1000 + source.size - 32 ?
        32 + rva - 0x1000 : null, message => warnings.push(message));

    assert.deepEqual(parsed, []);
    assert.deepEqual(warnings, []);
  });
}

void test("TD32 does not treat a valid footer inside another mapped section as overlay data", async () => {
  const source = file();
  const mapped = { ...section(32, source.size - 32), name: inlinePeSectionName(".text") };

  assert.deepEqual(await parseTd32Sources(source, [mapped], 32, [], () => null, () => {}), []);
});

void test("TD32 rejects malformed .debug ranges and retains visible warnings", async () => {
  const warnings: string[] = [];

  assert.deepEqual(await parseTd32Sources(file(), [section(0xffffffff, 0xffffffff)], 32,
    [], () => null, message => warnings.push(message)), []);
  assert.match(warnings.join(" | "), /bounds/);
  assert.equal(warnings.length, 1);
});

for (const [pointer, size] of [[0, 32], [32, 31], [33, 31]] as const) {
  void test(`TD32 does not suppress a source for an unmapped or differently bounded directory record: ${pointer}/${size}`, async () => {
    const entry = { ...createDebugViewEntry(0, 0x1000, pointer, size), td32: createTd32Info() };
    const source = file();
    const warnings: string[] = [];
    const parsed = await parseTd32Sources(source, [], 32, [entry], () => null, message => warnings.push(message));

    assert.equal(parsed.length, 1);
    assert.deepEqual(warnings, []);
  });
}

void test("TD32 caches a failed semantic decode across repeated container candidates", async context => {
  const source = file();
  const read = source.read.bind(source);
  let calls = 0;
  context.mock.method(source, "read", async (offset: number, size: number) => {
    if (++calls === 3) throw new Error("payload read failed");
    return read(offset, size);
  });
  const warnings: string[] = [];

  assert.deepEqual(await parseTd32Sources(source, [section(16, source.size - 16),
    section(32, source.size - 32)], 32, [], () => null, message => warnings.push(message)), []);
  assert.equal(warnings.filter(message => /payload read failed/.test(message)).length, 1);
});

void test("TD32 malformed anchored containers warn once instead of being decoded repeatedly", async () => {
  const source = new MockFile(Uint8Array.from([...new Uint8Array(32),
    ...new TextEncoder().encode("FB09"), 255, 255, 255, 255]));
  const warnings: string[] = [];

  const parsed = await parseTd32Sources(source, [section(32, 8), section(32, 8)], 32,
    [], () => null, message => warnings.push(message));
  assert.equal(parsed.length, 1);
  assert.deepEqual(parsed[0]?.td32.directories, []);
  assert.equal(warnings.filter(message => /subsection bounds/.test(message)).length, 1);
  assert.equal(new Set(warnings).size, warnings.length);
});

void test("TD32 keeps distinct containers and ignores directory entries without decoded TD32", async () => {
  const first = createTd32([], "FB09");
  const second = createTd32([], "FB0A");
  const source = new MockFile(Uint8Array.from([...new Uint8Array(32), ...first, ...second]));
  const warnings: string[] = [];
  const parsed = await parseTd32Sources(source, [section(32, first.length)], 32,
    [createDebugViewEntry(0, 0, 32, first.length)], () => null, message => warnings.push(message));

  assert.deepEqual(parsed.map(value => value.td32.signature), ["FB09", "FB0A"]);
  assert.deepEqual(warnings, []);
});
