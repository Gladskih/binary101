import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzePeDRuntime } from "../../../../analyzers/pe/d-runtime.js";
import { D_TEST_ABI, D_TEST_IO, D_TEST_MEMORY } from "../../../fixtures/d-runtime.js";
import {
  createLargePeDRuntimeFixture, createPaddedPeDRuntimeFixture, createPeDRuntimeFixture,
  createRenamedPeDRuntimeFixture,
  createDTableRelocations, rebaseDPeFixture, watchDModuleHeaderReads
} from "../../../fixtures/pe-d-runtime.js";

for (const pointerSize of [D_TEST_ABI.pointer32Bytes, D_TEST_ABI.pointer64Bytes]) {
  void test(`validates PE D metadata with ${pointerSize}-byte pointers and NULL padding`, async () => {
    const fixture = createPeDRuntimeFixture(pointerSize);

    const result = await analyzePeDRuntime(fixture.file, fixture.reader, fixture.core);

    assert.deepEqual(result?.modules, [fixture.module.record]);
    assert.deepEqual(result.warnings, []);
  });
}

void test("does no file I/O without a module-table candidate", async () => {
  const fixture = createPeDRuntimeFixture();
  fixture.core.sections = [fixture.dataSection, fixture.codeSection];
  fixture.reader.read = () => { throw new Error("Unexpected read on ordinary PE"); };

  assert.equal(await analyzePeDRuntime(fixture.file, fixture.reader, fixture.core), null);
});

void test("reports ambiguous named sections without reading tables", async () => {
  const fixture = createPeDRuntimeFixture();
  fixture.core.sections.push(fixture.tableSection);
  fixture.reader.read = () => { throw new Error("Unexpected table read"); };

  const result = await analyzePeDRuntime(fixture.file, fixture.reader, fixture.core);

  assert.deepEqual(result?.modules, []);
  assert.match(result.warnings.join(" "), /ambiguous/);
});

void test("reports invalid records while retaining valid modules", async () => {
  const fixture = createPeDRuntimeFixture();
  fixture.writeTable([0n, fixture.module.record.address, D_TEST_MEMORY.unmappedAddress]);

  const result = await analyzePeDRuntime(fixture.file, fixture.reader, fixture.core);

  assert.deepEqual(result?.modules, [fixture.module.record]);
  assert.match(result.warnings.join(" "),
    new RegExp(`Invalid.*0x${D_TEST_MEMORY.unmappedAddress.toString(16)}`));
});

void test("reports incomplete pointer tables", async () => {
  const fixture = createPeDRuntimeFixture();
  fixture.tableSection.virtualSize -= 1;

  const result = await analyzePeDRuntime(fixture.file, fixture.reader, fixture.core);

  assert.deepEqual(result?.modules, [fixture.module.record]);
  assert.match(result.warnings.join(" "), /incomplete pointer/);
});

void test("reports a table whose declared size exceeds its file backing", async () => {
  const fixture = createPeDRuntimeFixture();
  fixture.tableSection.virtualSize = fixture.tableSection.sizeOfRawData =
    D_TEST_IO.readWindowBytes + fixture.module.image.pointerSize;
  const result = await analyzePeDRuntime(fixture.file, fixture.reader, fixture.core);

  assert.match(result?.warnings.join(" ") ?? "", /truncated/);
});

void test("reports file read errors visibly", async () => {
  const fixture = createPeDRuntimeFixture();
  fixture.reader.read = async () => { throw new Error("I/O error"); };

  const result = await analyzePeDRuntime(fixture.file, fixture.reader, fixture.core);

  assert.deepEqual(result?.modules, []);
  assert.match(result.warnings.join(" "), /Could not read/);
});

void test("rejects references into zero-fill", async () => {
  const fixture = createPeDRuntimeFixture();
  fixture.dataSection.sizeOfRawData = D_TEST_ABI.headerBytes;

  const result = await analyzePeDRuntime(fixture.file, fixture.reader, fixture.core);

  assert.deepEqual(result?.modules, []);
  assert.match(result.warnings.join(" "), /Invalid/);
});

void test("parses all valid references beyond the removed metadata cap", async () => {
  const fixture = createLargePeDRuntimeFixture();

  const result = await analyzePeDRuntime(fixture.file, fixture.reader, fixture.core);

  assert.equal(result?.modules.length, fixture.recordCount);
  assert.deepEqual(result.warnings, []);
});

void test("parses all valid names beyond the removed metadata cap", async () => {
  const fixture = createLargePeDRuntimeFixture(0,
    "A".repeat(D_TEST_IO.readWindowBytes / Uint16Array.BYTES_PER_ELEMENT));

  const result = await analyzePeDRuntime(fixture.file, fixture.reader, fixture.core);

  assert.equal(result?.modules.length, fixture.recordCount);
  assert.deepEqual(result.warnings, []);
});

void test("discovers renamed tables and ignores duplicate and NULL slots", async () => {
  const fixture = createRenamedPeDRuntimeFixture();

  const result = await analyzePeDRuntime(fixture.file, fixture.reader, fixture.core, fixture.relocations);

  assert.deepEqual(result?.modules, [fixture.module.record, fixture.second.record]);
  assert.deepEqual(result.warnings, []);
});

void test("decodes overlapping candidates and the probed ModuleInfo only once", async () => {
  const fixture = createRenamedPeDRuntimeFixture();
  fixture.core.sections.push({ ...fixture.tableSection });
  const reads = watchDModuleHeaderReads(fixture);

  assert.match((await analyzePeDRuntime(fixture.file, fixture.reader, fixture.core,
    fixture.relocations))?.warnings.join(" ") ?? "", /ambiguous/);
  assert.deepEqual(reads, [fixture.dataSection.pointerToRawData,
    fixture.dataSection.pointerToRawData + Number(fixture.second.record.address -
      fixture.module.record.address)]);
});

void test("requires independent records rather than duplicate relocated pointers", async () => {
  const fixture = createRenamedPeDRuntimeFixture();
  fixture.writeTable([fixture.module.record.address, fixture.module.record.address]);
  fixture.relocations = createDTableRelocations(fixture.tableSection,
    [fixture.module.record.address, fixture.module.record.address], D_TEST_ABI.pointer64Bytes);

  assert.equal(await analyzePeDRuntime(fixture.file, fixture.reader, fixture.core,
    fixture.relocations), null);
});

void test("rejects imported module pointers below all mapped sections", async () => {
  const fixture = createPeDRuntimeFixture();
  fixture.module.write.importedModule(0, 0n);

  assert.equal((await analyzePeDRuntime(fixture.file, fixture.reader, fixture.core))?.modules.length, 0);
});

void test("rejects callbacks below their executable section", async () => {
  const fixture = createPeDRuntimeFixture();
  fixture.module.write.callback(0, fixture.module.record.address);

  assert.equal((await analyzePeDRuntime(fixture.file, fixture.reader, fixture.core))?.modules.length, 0);
});

void test("rejects callbacks at the virtual end even when raw padding remains", async () => {
  const fixture = createPeDRuntimeFixture();
  fixture.codeSection.virtualSize = fixture.module.image.pointerSize;
  fixture.module.write.callback(0, D_TEST_MEMORY.codeAddress +
    BigInt(fixture.codeSection.virtualSize));

  assert.equal((await analyzePeDRuntime(fixture.file, fixture.reader, fixture.core))?.modules.length, 0);
});

void test("declines incomplete renamed tables", async () => {
  const fixture = createRenamedPeDRuntimeFixture();
  fixture.reader.read = async () => new DataView(new ArrayBuffer(fixture.module.image.pointerSize - 1));

  assert.equal(await analyzePeDRuntime(fixture.file, fixture.reader, fixture.core, fixture.relocations), null);
});

void test("streams a complete named table larger than one read window", async () => {
  const fixture = createPaddedPeDRuntimeFixture();

  const result = await analyzePeDRuntime(fixture.file, fixture.reader, fixture.core);

  assert.deepEqual(result?.modules, [fixture.module.record, fixture.second.record]);
  assert.deepEqual(result.warnings, []);
});

void test("discovers a large renamed table using relocated slots beyond its first window", async () => {
  const fixture = createPaddedPeDRuntimeFixture();
  fixture.tableSection.name.value = ".renamed";

  const result = await analyzePeDRuntime(fixture.file, fixture.reader, fixture.core, fixture.relocations);

  assert.deepEqual(result?.modules, [fixture.module.record, fixture.second.record]);
  assert.deepEqual(result.warnings, []);
});

void test("declines a renamed table truncated after valid module pointers", async () => {
  const fixture = createPaddedPeDRuntimeFixture();
  fixture.tableSection.name.value = ".renamed";
  fixture.tableSection.virtualSize = fixture.tableSection.sizeOfRawData += fixture.module.image.pointerSize;

  assert.equal(await analyzePeDRuntime(fixture.file, fixture.reader, fixture.core,
    fixture.relocations), null);
});

void test("declines unreadable renamed tables", async () => {
  const fixture = createRenamedPeDRuntimeFixture();
  fixture.reader.read = async () => { throw new Error("I/O error"); };

  assert.equal(await analyzePeDRuntime(fixture.file, fixture.reader, fixture.core, fixture.relocations), null);
});

void test("declines renamed function-pointer tables without reading code", async () => {
  const fixture = createRenamedPeDRuntimeFixture();
  fixture.writeTable([0n, D_TEST_MEMORY.codeAddress, fixture.second.record.address]);

  assert.equal(await analyzePeDRuntime(fixture.file, fixture.reader, fixture.core, fixture.relocations), null);
});

void test("declines renamed tables with invalid records", async () => {
  const fixture = createRenamedPeDRuntimeFixture();
  fixture.second.write.flags(0);

  assert.equal(await analyzePeDRuntime(fixture.file, fixture.reader, fixture.core, fixture.relocations), null);
});

void test("declines renamed tables with imports outside the discovered module set", async () => {
  const fixture = createRenamedPeDRuntimeFixture();
  // A mapped pointer is insufficient: its target must also belong to the module table.
  fixture.module.write.importedModule(0, fixture.module.record.address +
    BigInt(fixture.module.image.pointerSize));

  assert.equal(await analyzePeDRuntime(fixture.file, fixture.reader, fixture.core, fixture.relocations), null);
});

void test("rejects ambiguous renamed tables", async () => {
  const fixture = createRenamedPeDRuntimeFixture();
  fixture.core.sections.push({ ...fixture.tableSection });

  const result = await analyzePeDRuntime(fixture.file, fixture.reader, fixture.core, fixture.relocations);

  assert.deepEqual(result?.modules, []);
  assert.match(result.warnings.join(" "), /ambiguous/);
});

void test("handles image bases above the PE32 address range", async () => {
  const fixture = createPeDRuntimeFixture();
  // Beyond the four-byte address range; the parser must retain the full VA.
  rebaseDPeFixture(fixture, 1n << 32n);

  const result = await analyzePeDRuntime(fixture.file, fixture.reader, fixture.core);

  assert.deepEqual(result?.warnings, []);
  assert.equal(result.modules[0]?.address, fixture.core.opt.ImageBase + fixture.module.record.address);
  assert.equal(result.modules[0]?.callbacks[0]?.address,
    fixture.core.opt.ImageBase + fixture.module.record.callbacks[0]!.address);
});

void test("rejects non-file-backed callbacks", async () => {
  const fixture = createPeDRuntimeFixture();
  fixture.codeSection.pointerToRawData = fixture.reader.size;

  assert.equal((await analyzePeDRuntime(fixture.file, fixture.reader, fixture.core))?.modules.length, 0);
});

void test("rejects module headers immediately beyond a mapped section", async () => {
  const fixture = createPeDRuntimeFixture();
  fixture.writeTable([0n, fixture.module.record.address + BigInt(fixture.dataSection.virtualSize)]);

  assert.equal((await analyzePeDRuntime(fixture.file, fixture.reader, fixture.core))?.modules.length, 0);
});

void test("reports tables truncated at EOF even with an aligned declared size", async () => {
  const fixture = createPeDRuntimeFixture();
  fixture.tableSection.pointerToRawData = fixture.reader.size - fixture.module.image.pointerSize;

  assert.match((await analyzePeDRuntime(fixture.file, fixture.reader, fixture.core))?.warnings.join(" ") ?? "",
    /truncated/);
});

void test("discovers valid renamed metadata beyond the removed cap", async () => {
  const fixture = createLargePeDRuntimeFixture();
  fixture.tableSection.name.value = ".renamed";

  const result = await analyzePeDRuntime(fixture.file, fixture.reader, fixture.core, fixture.relocations);

  assert.equal(result?.modules.length, fixture.recordCount);
  assert.deepEqual(result.warnings, []);
});

void test("uses raw size for sections with a zero virtual size", async () => {
  const fixture = createPeDRuntimeFixture();
  fixture.tableSection.virtualSize = fixture.dataSection.virtualSize = fixture.codeSection.virtualSize = 0;

  const result = await analyzePeDRuntime(fixture.file, fixture.reader, fixture.core);

  assert.deepEqual(result?.modules, [fixture.module.record]);
  assert.deepEqual(result.warnings, []);
});
