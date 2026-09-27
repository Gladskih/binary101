import assert from "node:assert/strict";
import { test } from "node:test";
import { readRegistryResource, createRegistryResourceReader } from "../../../../../../analyzers/pe/resources/preview/registry-resource.js";
import { createPreviewLangEntry } from "../../../../../helpers/pe-resource-preview-fixture.js";
import { MockFile } from "../../../../../helpers/mock-file.js";

// I/O policy oracle: the shared reader's window is 64 KiB = 64 * 1024 = 65536 bytes.
// See analyzers/file-range-reader.ts; these tests pin that policy independently.
// 1 MiB = 1024 * 1024 forces 16 full windows plus the final declaration (17 reads).
// CP 65001 = UTF-8: https://learn.microsoft.com/en-us/windows/win32/intl/code-page-identifiers
// RVA limits 0xffffffff / 0x100000000 = 2^32 - 1 / 2^32 (4-byte Data RVA):
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#resource-data-entry
void test("registry resource reads follow file bounds and retain the last declaration", async () => {
  const file = new MockFile(new TextEncoder().encode(" ".repeat(1024 * 1024) + "HKCU { Last }"));
  const reads: Array<[number, number]> = [];
  const original = file.readBytes.bind(file);
  file.readBytes = (offset, size) => { reads.push([offset, size]); return original(offset, size); };
  const result = await readRegistryResource(file, createPreviewLangEntry(0, file.size, 65001));
  assert.equal(result.preview?.registry?.roots[0]?.children[0]?.name, "Last");
  assert.equal(result.preview?.textPreview?.length, file.size);
  assert.equal(result.issues, undefined);
  assert.equal(reads.length, 17);
  assert.deepEqual(reads.at(-1), [1024 * 1024, "HKCU { Last }".length]);
  assert.ok(reads.every(([offset, size]) => size <= 65536 && offset + size <= file.size));
});

void test("registry decoder carries UTF-8 multibyte sequences across file windows", async () => {
  const file = new MockFile(new TextEncoder().encode(" ".repeat(65535 - "HKCU { '".length) + "HKCU { 'П' }"));
  const result = await readRegistryResource(file, createPreviewLangEntry(0, file.size, 65001));
  assert.equal(result.preview?.registry?.roots[0]?.children[0]?.name, "П");
  assert.equal(result.issues, undefined);
});

void test("unspecified resource code page accepts ASCII without uncertainty", async () => {
  const file = new MockFile(new TextEncoder().encode("HKCU { Good }"));
  const entry = createPreviewLangEntry(0, file.size);
  Reflect.deleteProperty(entry, "codePage");
  assert.equal((await readRegistryResource(file, entry)).issues, undefined);
});

void test("mapped reads cannot wrap the 32-bit PE RVA address space", async () => {
  const file = new MockFile(new Uint8Array([65, 66]));
  const reads: Array<[number, number]> = [];
  const reader = Object.assign(file, { readResourceBytes: (rva: number, size: number) => {
    reads.push([rva, size]);
    return file.readBytes(0, size);
  } });
  const result = await readRegistryResource(reader,
    createPreviewLangEntry(0xffff_ffff, 2, 65001, 1033, 0));
  assert.deepEqual(reads, [[0xffff_ffff, 1]]);
  assert.equal(result.preview?.textPreview, "A");
  assert.match(result.issues?.join(" ") ?? "", /fewer bytes/);
});

void test("mapped RVA reads advance through every available window", async () => {
  const file = new MockFile(new TextEncoder().encode(" ".repeat(65536) + "HKCU { Last }"));
  const reads: Array<[number, number]> = [];
  const reader = Object.assign(file, { readResourceBytes: (rva: number, size: number) => {
    reads.push([rva, size]);
    return file.readBytes(rva - 0x2000, size);
  } });
  const result = await readRegistryResource(reader, createPreviewLangEntry(0x2000, file.size, 65001, 1033, 0));
  assert.equal(result.preview?.registry?.roots[0]?.children[0]?.name, "Last");
  assert.deepEqual(reads, [[0x2000, 65536], [0x12000, "HKCU { Last }".length]]);
  assert.equal(result.issues, undefined);
});

void test("a short mapped read stops at the first missing RVA byte", async () => {
  const file = new MockFile(new TextEncoder().encode("HKCU { Good }"));
  const reads: number[] = [];
  const reader = Object.assign(file, { readResourceBytes: (rva: number, size: number) => {
    reads.push(rva);
    return file.readBytes(0, size);
  } });
  const result = await readRegistryResource(reader, createPreviewLangEntry(0x2000, 200000, 65001, 1033, 0));
  assert.deepEqual(reads, [0x2000]);
  assert.equal(result.preview?.registry?.roots[0]?.children[0]?.name, "Good");
  assert.deepEqual(result.issues, ["Resource preview read fewer bytes than the declared data size."]);
});

void test("read failures retain earlier declarations and report the unavailable range", async () => {
  const file = new MockFile(new TextEncoder().encode("HKCU { Good }" + " ".repeat(65536)));
  const original = file.readBytes.bind(file);
  file.readBytes = (offset, size) => offset ? Promise.reject(new Error("unavailable")) : original(offset, size);
  const result = await readRegistryResource(file, createPreviewLangEntry(0, file.size, 65001));
  assert.equal(result.preview?.registry?.roots[0]?.children[0]?.name, "Good");
  assert.match(result.issues?.join(" ") ?? "", /could not be read/);
  assert.match(result.issues?.join(" ") ?? "", /fewer bytes/);
});

for (const dataFileOffset of [null, -1]) {
  void test(`unmapped resource offset ${dataFileOffset} is diagnosed`, async () => {
    const result = await readRegistryResource(new MockFile(new Uint8Array(2)),
      createPreviewLangEntry(1, 1, 0, 1033, dataFileOffset));
    assert.deepEqual(result, { issues: ["Resource RVA could not be mapped to a file offset."] });
  });
}

for (const entry of [
  createPreviewLangEntry(0, -1), createPreviewLangEntry(0, Number.NaN),
  createPreviewLangEntry(0, 1.5), createPreviewLangEntry(0, Number.POSITIVE_INFINITY),
  createPreviewLangEntry(-1, 1, 0, 1033, 0), createPreviewLangEntry(0x1_0000_0000, 1, 0, 1033, 0),
  createPreviewLangEntry(0, 1, 0, 1033, 0.5), createPreviewLangEntry(0, 1, 0, 1033, Number.NaN)
]) {
  void test(`invalid registry resource range ${JSON.stringify(entry)} is rejected`, async () => {
    const result = await readRegistryResource(new MockFile(new Uint8Array(2)), entry);
    assert.deepEqual(result, { issues: ["ATL RGS: invalid resource file/RVA range."] });
  });
}

void test("empty and entirely unavailable resources remain reviewable", async () => {
  const file = new MockFile(new Uint8Array(2));
  const empty = await readRegistryResource(file, createPreviewLangEntry(0, 0));
  const outside = await readRegistryResource(file, createPreviewLangEntry(3, 2));
  assert.equal(empty.preview?.registry?.roots.length, 0);
  assert.deepEqual(empty.issues, ["ATL RGS: script is empty or has no root hives."]);
  assert.deepEqual(outside.issues, ["Resource preview read fewer bytes than the declared data size.",
    "ATL RGS: script is empty or has no root hives."]);
});

void test("aliased registry payloads reuse a single concurrent read and decode", async () => {
  const file = new MockFile(new TextEncoder().encode("HKCU { Good }"));
  const reads: number[] = [];
  const original = file.readBytes.bind(file);
  file.readBytes = (offset, size) => { reads.push(size); return original(offset, size); };
  const readRegistry = createRegistryResourceReader(file);
  const results = await Promise.all([
    readRegistry(createPreviewLangEntry(0, file.size, 65001, 1033)),
    readRegistry(createPreviewLangEntry(0, file.size, 65001, 1049))
  ]);
  assert.deepEqual(reads, [file.size]);
  assert.strictEqual(results[0], results[1]);
  assert.equal(results[0]?.preview?.registry?.roots[0]?.children[0]?.name, "Good");
});

void test("registry cache distinguishes resource extents, file offsets, RVAs and code pages", async () => {
  const file = new MockFile(new TextEncoder().encode("HKCU { 'П' }"));
  const readRegistry = createRegistryResourceReader(file);
  const complete = await readRegistry(createPreviewLangEntry(0, file.size, 65001));
  const ansi = await readRegistry(createPreviewLangEntry(0, file.size, 1251));
  assert.equal(complete.preview?.registry?.roots[0]?.children[0]?.name, "П");
  assert.equal(ansi.preview?.textEncoding, "windows-1251");
  assert.notEqual(ansi.preview?.textPreview, complete.preview?.textPreview);
  assert.notStrictEqual(await readRegistry(createPreviewLangEntry(0, file.size - 1, 65001)), complete);
  assert.notStrictEqual(await readRegistry(createPreviewLangEntry(0, file.size, 65001, 1033, 1)), complete);
  assert.notStrictEqual(await readRegistry(createPreviewLangEntry(1, file.size, 65001, 1033, 0)), complete);
});

void test("registry cache keys preserve boundaries between numeric range fields", async () => {
  const file = new MockFile(new TextEncoder().encode(" HKCU { One } HKCU { Two }"));
  const readRegistry = createRegistryResourceReader(file);
  // Concatenating offset/size without a separator would merge 1/23 and 12/3.
  assert.notStrictEqual(await readRegistry(createPreviewLangEntry(0, 23, 65001, 1033, 1)),
    await readRegistry(createPreviewLangEntry(0, 3, 65001, 1033, 12)));
});
