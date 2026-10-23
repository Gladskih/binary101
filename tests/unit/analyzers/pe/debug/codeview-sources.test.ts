import assert from "node:assert/strict";
import { test } from "node:test";
import { parseCodeViewSources } from "../../../../../analyzers/pe/debug/codeview-sources.js";
import { createPeCodeViewOverlay, createPeDirectHll } from "../../../../fixtures/pe-codeview-locations.js";
import { createHll } from "../../../../fixtures/pe-hll.js";
import { inlinePeSectionName } from "../../../../../analyzers/pe/sections/name.js";
import { MockFile } from "../../../../helpers/mock-file.js";
import { parsePe, isPeWindowsParseResult } from "../../../../../analyzers/pe/index.js";
import { createDebugViewEntry } from "../../../../fixtures/pe-debug-view-subject.js";

const unmappedRva = () => null;

const section = (offset: number, size: number) => ({ name: inlinePeSectionName(".debug"),
  virtualAddress: 0x1000, virtualSize: size, pointerToRawData: offset, sizeOfRawData: size, characteristics: 0 });

for (const [create, kind] of [[createPeCodeViewOverlay, "overlay"], [createPeDirectHll, "directory"]] as const) {
  void test(`Standalone NB04 ${kind} reaches the full PE result without a fabricated directory entry`, async () => {
    const source = create();
    const pe = await parsePe(source);
    assert.ok(pe && isPeWindowsParseResult(pe));
    assert.equal(pe.debug?.codeViewSources?.length, 1);
    assert.equal(pe.debug?.codeViewSources?.[0]!.kind, kind);
    assert.equal(pe.debug?.entries, undefined);
    assert.equal(pe.debug?.warning, undefined);
    assert.deepEqual(pe.debug?.rawDataRanges, [{ start: pe.debug!.codeViewSources![0]!.offset,
      end: pe.debug!.codeViewSources![0]!.offset + pe.debug!.codeViewSources![0]!.size }]);
  });
}

void test("CodeView source sections deduplicate repeated ranges and already decoded directory payloads", async () => {
  const payload = createHll([]);
  const file = new MockFile(Uint8Array.from([...new Uint8Array(32), ...payload]));
  const warnings: string[] = [];
  const sections = [section(32, payload.length), section(32, payload.length)];
  const found = await parseCodeViewSources(file, sections, 32, [], [], unmappedRva, warning => warnings.push(warning));
  const entry = { ...createDebugViewEntry(2, 0x1000, 32, payload.length), legacyCodeView: found[0]!.legacyCodeView };
  const skipped = await parseCodeViewSources(file, sections, 32, [entry], [], unmappedRva,
    warning => warnings.push(warning));
  assert.equal(found.length, 1);
  assert.equal(found[0]!.kind, "section");
  assert.deepEqual(skipped, []);
  assert.deepEqual(warnings, []);
});

void test("CodeView source anchors do not scan arbitrary image bytes for signatures", async () => {
  const file = new MockFile(Uint8Array.from([...new Uint8Array(32), ...createHll([]), ...new Uint8Array(32)]));
  const warnings: string[] = [];
  const found = await parseCodeViewSources(file, [], file.size, [], [], unmappedRva, warning => warnings.push(warning));
  assert.deepEqual(found, []);
  assert.deepEqual(warnings, []);
});

void test("CodeView source discovery keeps separate .debug ranges and ignores other section names", async () => {
  const payload = createHll([]);
  const file = new MockFile(Uint8Array.from([...new Uint8Array(32), ...payload, ...payload, ...payload]));
  const warnings: string[] = [];
  const sections = [section(32, payload.length), section(32 + payload.length, payload.length),
    { ...section(32 + payload.length * 2, payload.length), name: inlinePeSectionName(".text") }];
  const data = await parseCodeViewSources(file, sections, 0, [], [], unmappedRva, warning => warnings.push(warning));
  assert.deepEqual(data.map(source => source.offset), [32, 32 + payload.length]);
  assert.deepEqual(warnings, []);
});

void test("CodeView direct and section anchors deduplicate the same nested container", async () => {
  const payload = createHll([]);
  const file = new MockFile(Uint8Array.from([...new Uint8Array(32), ...payload]));
  const warnings: string[] = [];
  const data = await parseCodeViewSources(file, [section(0, file.size)], 0, [],
    [{ index: 6, name: "DEBUG", rva: 0x1000, size: payload.length }], rva => rva - 0x1000 + 32,
    warning => warnings.push(warning));
  assert.equal(data.length, 1);
  assert.equal(data[0]!.kind, "directory");
  assert.deepEqual(warnings, []);
});

void test("CodeView unreadable anchored payloads and non-CodeView entries do not suppress source discovery", async () => {
  const payload = createHll([]);
  const file = new MockFile(Uint8Array.from([...new Uint8Array(32), ...payload]));
  const warnings: string[] = [];
  const entry = createDebugViewEntry(0, 0, 32, payload.length);
  const data = await parseCodeViewSources(file, [], 32, [entry], [], unmappedRva, warning => warnings.push(warning));
  assert.equal(data.length, 1);
  const broken = new MockFile(Uint8Array.from([0, 78, 66, 48, 52, 255, 255, 255, 255]));
  assert.deepEqual(await parseCodeViewSources(broken, [], 1, [], [], unmappedRva,
    warning => warnings.push(warning)), []);
  assert.match(warnings[0]!, /bounds/);
});

void test("CodeView already decoded directory locations honor RVA mapping and exact physical ends", async () => {
  const payload = createHll([]);
  const file = new MockFile(Uint8Array.from([...new Uint8Array(32), ...payload]));
  const warnings: string[] = [];
  const parsed = (await parseCodeViewSources(file, [], 32, [], [], unmappedRva, warning => warnings.push(warning)))[0]!;
  const entry = { ...createDebugViewEntry(2, 0x1000, 0, payload.length), legacyCodeView: parsed.legacyCodeView };
  assert.deepEqual(await parseCodeViewSources(file, [], 32, [entry], [], rva => rva - 0x1000 + 32,
    warning => warnings.push(warning)), []);
  assert.equal((await parseCodeViewSources(file, [], 32, [entry], [], unmappedRva,
    warning => warnings.push(warning))).length, 1);
  assert.equal((await parseCodeViewSources(file, [], 32, [{ ...entry, sizeOfData: file.size }], [], unmappedRva,
    assert.fail)).length, 1);
  assert.equal((await parseCodeViewSources(file, [], 32, [{ ...entry, pointerToRawData: 31 }], [], unmappedRva,
    warning => warnings.push(warning))).length, 1);
  assert.equal((await parseCodeViewSources(file, [], 32, [{ ...entry, pointerToRawData: 33 }], [], unmappedRva,
    warning => warnings.push(warning))).length, 1);
  assert.equal((await parseCodeViewSources(file, [], 32,
    [{ ...entry, pointerToRawData: 33, sizeOfData: payload.length - 1 }], [], unmappedRva, assert.fail)).length, 1);
  assert.deepEqual(warnings, []);
});

void test("CodeView repeated candidate ranges are not read again and oversized sections remain diagnostic", async context => {
  const payload = createHll([]);
  const file = new MockFile(Uint8Array.from([...new Uint8Array(32), ...payload]));
  const read = file.read.bind(file);
  let reads = 0;
  context.mock.method(file, "read", async (offset: number, size: number) => { reads++; return read(offset, size); });
  await parseCodeViewSources(file, [section(32, payload.length)], 32, [], [], unmappedRva, assert.fail);
  const initial = reads;
  reads = 0;
  await parseCodeViewSources(file, [section(32, payload.length), section(32, payload.length)],
    32, [], [], unmappedRva, assert.fail);
  assert.equal(reads, initial);
  const warnings: string[] = [];
  assert.deepEqual(await parseCodeViewSources(file, [section(32, payload.length + 1)], 32, [], [], unmappedRva,
    warning => warnings.push(warning)), []);
  assert.equal(warnings.length, 1);
  assert.match(warnings[0]!, /candidate range exceeds file bounds/);
});

void test("CodeView a decoded disjoint directory entry cannot suppress a separate .debug container", async () => {
  const payload = createHll([]);
  const file = new MockFile(Uint8Array.from([...new Uint8Array(32), ...payload, ...payload]));
  const first = (await parseCodeViewSources(file, [section(32, payload.length * 2)],
    32, [], [], unmappedRva, assert.fail))[0]!;
  const entry = { ...createDebugViewEntry(2, 0, 32, payload.length), legacyCodeView: first.legacyCodeView };
  const data = await parseCodeViewSources(file, [section(32 + payload.length, payload.length)], 32,
    [entry], [], unmappedRva, assert.fail);
  assert.equal(data.length, 1);
  assert.equal(data[0]!.offset, 32 + payload.length);
});
