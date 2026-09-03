"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElf } from "../../../../analyzers/elf/index.js";
import { analyzeElfNativeAot } from "../../../../analyzers/elf/native-aot.js";
import { createElfNativeAotFixture } from "../../../helpers/elf-native-aot-fixture.js";
import { MockFile } from "../../../helpers/mock-file.js";

const parseFixture = async (bytes: Uint8Array) =>
  parseElf(new MockFile(bytes, "native-aot.elf", "application/x-elf"));

const useDynamicRelaTable = (
  fixture: ReturnType<typeof createElfNativeAotFixture>,
  entrySize = 24
): void => {
  const view = new DataView(fixture.bytes.buffer);
  view.setUint16(56, 2, true);
  const dynamicProgramHeader = 64 + 56;
  const dynamicOffset = 0x300;
  view.setUint32(dynamicProgramHeader, 2, true);
  view.setUint32(dynamicProgramHeader + 4, 6, true);
  view.setBigUint64(dynamicProgramHeader + 8, BigInt(dynamicOffset), true);
  view.setBigUint64(dynamicProgramHeader + 16, BigInt(dynamicOffset), true);
  view.setBigUint64(dynamicProgramHeader + 32, 64n, true);
  view.setBigUint64(dynamicProgramHeader + 40, 64n, true);
  view.setBigUint64(dynamicProgramHeader + 48, 8n, true);
  view.setBigInt64(dynamicOffset, 7n, true);
  view.setBigUint64(dynamicOffset + 8, BigInt(fixture.relocationOffset), true);
  view.setBigInt64(dynamicOffset + 16, 8n, true);
  view.setBigUint64(dynamicOffset + 24, BigInt(fixture.relocationCount * 24), true);
  view.setBigInt64(dynamicOffset + 32, 9n, true);
  view.setBigUint64(dynamicOffset + 40, BigInt(entrySize), true);
  view.setBigInt64(dynamicOffset + 48, 0n, true);
  view.setUint32(fixture.sectionHeaderOffset + 64 + 4, 1, true);
};

void test("parseElf confirms NativeAOT through ELF64 RELA relocations", async () => {
  const fixture = createElfNativeAotFixture();

  const parsed = await parseElf(fixture.file);

  assert.equal(parsed?.nativeAot?.status, "confirmed");
  assert.equal(parsed?.nativeAot?.headerRva, fixture.headerAddress);
  assert.equal(parsed?.nativeAot?.modulePointerRva, fixture.modulePointerAddress);
  assert.equal(parsed?.nativeAot?.sections.length, 2);
  assert.deepEqual(parsed?.issues, []);
});

void test("parseElf resolves implicit addends from ELF64 REL relocations", async () => {
  const fixture = createElfNativeAotFixture();
  const view = new DataView(fixture.bytes.buffer);
  for (let index = 0; index < fixture.relocationCount; index += 1) {
    const source = fixture.relocationOffset + index * 24;
    const destination = fixture.relocationOffset + index * 16;
    const location = view.getBigUint64(source, true);
    const target = view.getBigInt64(source + 16, true);
    view.setBigUint64(Number(location), BigInt(target), true);
    view.setBigUint64(destination, location, true);
    view.setBigUint64(destination + 8, 8n, true);
  }
  const section = fixture.sectionHeaderOffset + 64;
  view.setUint32(section + 4, 9, true);
  view.setBigUint64(section + 32, BigInt(fixture.relocationCount * 16), true);
  view.setBigUint64(section + 56, 16n, true);

  const parsed = await parseFixture(fixture.bytes);

  assert.equal(parsed?.nativeAot?.status, "confirmed");
});

void test("parseElf falls back to PT_DYNAMIC when section headers do not expose relocations", async () => {
  const fixture = createElfNativeAotFixture();
  useDynamicRelaTable(fixture);

  const parsed = await parseFixture(fixture.bytes);

  assert.equal(parsed?.nativeAot?.status, "confirmed");
});

void test("parseElf reports a malformed dynamic relocation table", async () => {
  const fixture = createElfNativeAotFixture();
  useDynamicRelaTable(fixture, 16);

  const parsed = await parseFixture(fixture.bytes);

  assert.equal(parsed?.nativeAot, undefined);
  assert.ok(parsed?.issues.some(issue => issue.includes("dynamic RELA table")));
});

void test("parseElf reports malformed PT_DYNAMIC geometry", async () => {
  const fixture = createElfNativeAotFixture();
  useDynamicRelaTable(fixture);
  new DataView(fixture.bytes.buffer).setBigUint64(64 + 56 + 32, 63n, true);

  const parsed = await parseFixture(fixture.bytes);

  assert.equal(parsed?.nativeAot, undefined);
  assert.ok(parsed?.issues.some(issue => issue.includes("PT_DYNAMIC table")));
});

void test("parseElf rejects conflicting dynamic relocation tags", async () => {
  const fixture = createElfNativeAotFixture();
  useDynamicRelaTable(fixture);
  const view = new DataView(fixture.bytes.buffer);
  view.setBigInt64(0x330, 7n, true);
  view.setBigUint64(0x338, BigInt(fixture.relocationOffset + 24), true);

  const parsed = await parseFixture(fixture.bytes);

  assert.equal(parsed?.nativeAot, undefined);
  assert.ok(parsed?.issues.some(issue => issue.includes("conflicting relocation tags")));
});

void test("parseElf ignores relocation sections that are not loaded", async () => {
  const fixture = createElfNativeAotFixture();
  new DataView(fixture.bytes.buffer).setBigUint64(
    fixture.sectionHeaderOffset + 64 + 8,
    0n,
    true
  );

  const parsed = await parseFixture(fixture.bytes);

  assert.equal(parsed?.nativeAot, undefined);
  assert.deepEqual(parsed?.issues, []);
});

void test("parseElf rejects unsupported envelopes before NativeAOT analysis", async () => {
  const relocatable = createElfNativeAotFixture();
  new DataView(relocatable.bytes.buffer).setUint16(16, 1, true);
  const bigEndian = createElfNativeAotFixture();
  new DataView(bigEndian.bytes.buffer).setUint8(5, 2);
  const unsupportedMachine = createElfNativeAotFixture();
  new DataView(unsupportedMachine.bytes.buffer).setUint16(18, 0, true);

  const results = await Promise.all([
    parseFixture(relocatable.bytes),
    parseFixture(bigEndian.bytes),
    parseFixture(unsupportedMachine.bytes)
  ]);

  assert.deepEqual(results.map(result => result?.nativeAot), [undefined, undefined, undefined]);
});

void test("parseElf reports malformed relocation tables without throwing", async () => {
  const fixture = createElfNativeAotFixture();
  const section = fixture.sectionHeaderOffset + 64;
  new DataView(fixture.bytes.buffer).setBigUint64(section + 56, 23n, true);

  const parsed = await parseFixture(fixture.bytes);

  assert.equal(parsed?.nativeAot, undefined);
  assert.ok(parsed?.issues.some(issue => issue.includes("relocation section")));
});

void test("parseElf does not accept non-relative or symbol-backed relocation evidence", async () => {
  const wrongType = createElfNativeAotFixture();
  new DataView(wrongType.bytes.buffer).setBigUint64(wrongType.relocationOffset + 8, 7n, true);
  const symbolBacked = createElfNativeAotFixture();
  new DataView(symbolBacked.bytes.buffer).setBigUint64(
    symbolBacked.relocationOffset + 8,
    (1n << 32n) | 8n,
    true
  );

  const results = await Promise.all([parseFixture(wrongType.bytes), parseFixture(symbolBacked.bytes)]);

  assert.deepEqual(results.map(result => result?.nativeAot), [undefined, undefined]);
});

void test("parseElf rejects relative relocations with invalid sites and targets", async () => {
  const invalidSite = createElfNativeAotFixture();
  new DataView(invalidSite.bytes.buffer).setBigUint64(
    invalidSite.relocationOffset,
    BigInt(invalidSite.bytes.byteLength + 8),
    true
  );
  const negativeTarget = createElfNativeAotFixture();
  new DataView(negativeTarget.bytes.buffer).setBigInt64(
    negativeTarget.relocationOffset + 16,
    -1n,
    true
  );
  const oversizedTarget = createElfNativeAotFixture();
  new DataView(oversizedTarget.bytes.buffer).setBigInt64(
    oversizedTarget.relocationOffset + 16,
    BigInt(Number.MAX_SAFE_INTEGER) + 1n,
    true
  );

  const results = await Promise.all([
    parseFixture(invalidSite.bytes),
    parseFixture(negativeTarget.bytes),
    parseFixture(oversizedTarget.bytes)
  ]);

  assert.deepEqual(results.map(result => result?.nativeAot), [undefined, undefined, undefined]);
});

void test("parseElf rejects conflicting relative relocations", async () => {
  const fixture = createElfNativeAotFixture();
  const view = new DataView(fixture.bytes.buffer);
  const firstLocation = view.getBigUint64(fixture.relocationOffset, true);
  const firstTarget = view.getBigInt64(fixture.relocationOffset + 16, true);
  view.setBigUint64(fixture.relocationOffset + 24, firstLocation, true);
  view.setBigInt64(fixture.relocationOffset + 40, firstTarget + 1n, true);

  const parsed = await parseFixture(fixture.bytes);

  assert.equal(parsed?.nativeAot, undefined);
  assert.ok(parsed?.issues.some(issue => issue.includes("Conflicting")));
});

void test("ELF NativeAOT analysis contains file read failures", async () => {
  const fixture = createElfNativeAotFixture();
  const parsed = await parseElf(fixture.file);
  assert.ok(parsed);
  class FailingFile extends MockFile {
    override slice(start?: number, end?: number, contentType?: string): Blob {
      if ((start ?? 0) >= fixture.relocationOffset) throw new Error("read failed");
      return super.slice(start, end, contentType);
    }
  }
  const issues: string[] = [];

  const metadata = await analyzeElfNativeAot(
    new FailingFile(fixture.bytes),
    parsed.header,
    parsed.programHeaders,
    parsed.sections,
    parsed.is64,
    parsed.littleEndian,
    issues
  );

  assert.equal(metadata, null);
  assert.deepEqual(issues, ["ELF NativeAOT relocation data is truncated or malformed."]);
});

void test("ELF NativeAOT analysis requires a loadable image", async () => {
  const fixture = createElfNativeAotFixture();
  const parsed = await parseElf(fixture.file);
  assert.ok(parsed);

  const metadata = await analyzeElfNativeAot(
    fixture.file,
    parsed.header,
    [],
    parsed.sections,
    parsed.is64,
    parsed.littleEndian,
    []
  );

  assert.equal(metadata, null);
});
