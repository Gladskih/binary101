"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseManagedResources } from "../../../../../analyzers/pe/clr/managed-resources.js";
import type { PeClrHeader, PeClrManifestResourceInfo, PeClrMeta } from "../../../../../analyzers/pe/clr/types.js";
import { createPngFile } from "../../../../fixtures/image-sample-files.js";
import { MockFile } from "../../../../helpers/mock-file.js";

import { makeDotNetResources, stringResourceValue } from "../../../../fixtures/dotnet-resource-file.js";

const textEncoder = new TextEncoder();
const CLR_FILE_TABLE_ID = 0x26; // ECMA-335 II.22.19 File table id.
const CLR_ASSEMBLY_REF_TABLE_ID = 0x23; // ECMA-335 II.22.5 AssemblyRef table id.

const makeManagedResourceFixture = (): { bytes: Uint8Array; directorySize: number; resourceRva: number } => {
  const directorySize = Uint8Array.BYTES_PER_ELEMENT << 8;
  const resourceRva = directorySize / 2;
  return {
    bytes: new Uint8Array(resourceRva + directorySize * 2),
    directorySize,
    resourceRva
  };
};

const makeClr = (
  resourcesRva: number,
  rows: PeClrManifestResourceInfo[],
  resourcesSize: number
): PeClrHeader => ({
  cb: 0x48, // ECMA-335 II.25.3.3 current CLR header size.
  MajorRuntimeVersion: 4,
  MinorRuntimeVersion: 0,
  MetaDataRVA: 0,
  MetaDataSize: 0,
  Flags: 0,
  EntryPointToken: 0,
  ResourcesRVA: resourcesRva,
  ResourcesSize: resourcesSize,
  StrongNameSignatureRVA: 0,
  StrongNameSignatureSize: 0,
  CodeManagerTableRVA: 0,
  CodeManagerTableSize: 0,
  VTableFixupsRVA: 0,
  VTableFixupsSize: 0,
  ExportAddressTableJumpsRVA: 0,
  ExportAddressTableJumpsSize: 0,
  ManagedNativeHeaderRVA: 0,
  ManagedNativeHeaderSize: 0,
  meta: makeResourceMetadata(rows)
});

const makeResourceMetadata = (rows: PeClrManifestResourceInfo[]): PeClrMeta => ({
  streams: [],
  tables: { manifestResources: rows } as NonNullable<PeClrMeta["tables"]>
});

const makeRow = (
  name: string,
  offset: number,
  implementation: PeClrManifestResourceInfo["implementation"] =
    { table: "null", tableId: -1, row: 0, raw: 0, valid: true }
): PeClrManifestResourceInfo => ({
  row: 1,
  name,
  offset,
  flags: 1,
  implementation
});

const putPayload = (target: Uint8Array, offset: number, payload: Uint8Array): void => {
  const view = new DataView(target.buffer);
  view.setUint32(offset, payload.length, true);
  target.set(payload, offset + 4);
};

const generatedLabel = (prefix: string, index: number): string => `${prefix}-${index.toString(36)}`;
const generatedTextPayload = (index: number): string => JSON.stringify({ value: generatedLabel("payload", index) });

void test("parseManagedResources renders direct text payloads through existing preview sniffing", async () => {
  const fixture = makeManagedResourceFixture();
  const textPayload = `${generatedTextPayload(0)}\n`;
  putPayload(fixture.bytes, fixture.resourceRva, textEncoder.encode(textPayload));

  const parsed = await parseManagedResources(
    new MockFile(fixture.bytes),
    rva => rva,
    makeClr(fixture.resourceRva, [makeRow(generatedLabel("raw", 0), 0)], fixture.directorySize)
  );

  assert.strictEqual(parsed?.entries[0]?.storage, "embedded");
  assert.strictEqual(parsed?.entries[0]?.previewKind, "text");
  assert.strictEqual(parsed?.entries[0]?.textPreview, textPayload);
});

void test("parseManagedResources renders direct PNG payloads through existing preview sniffing", async () => {
  const fixture = makeManagedResourceFixture();
  putPayload(fixture.bytes, fixture.resourceRva, createPngFile().data);

  const parsed = await parseManagedResources(
    new MockFile(fixture.bytes),
    rva => rva,
    makeClr(fixture.resourceRva, [makeRow(generatedLabel("image", 0), 0)], fixture.directorySize)
  );

  assert.strictEqual(parsed?.entries[0]?.previewKind, "image");
  assert.strictEqual(parsed?.entries[0]?.previewMime, "image/png");
});

void test("parseManagedResources treats nil Implementation coded indexes as embedded", async () => {
  const fixture = makeManagedResourceFixture();
  const textPayload = `${generatedTextPayload(1)}\n`;
  putPayload(fixture.bytes, fixture.resourceRva, textEncoder.encode(textPayload));

  const parsed = await parseManagedResources(
    new MockFile(fixture.bytes),
    rva => rva,
    makeClr(fixture.resourceRva, [
      makeRow(generatedLabel("nil-implementation", 0), 0, {
        table: "File",
        tableId: CLR_FILE_TABLE_ID,
        row: 0,
        raw: 0,
        tag: 0,
        valid: true
      })
    ], fixture.directorySize)
  );

  assert.strictEqual(parsed?.entries[0]?.storage, "embedded");
  assert.strictEqual(parsed?.entries[0]?.size, textEncoder.encode(textPayload).length);
  assert.strictEqual(parsed?.entries[0]?.textPreview, textPayload);
});

void test("parseManagedResources decodes safe primitive .resources entries", async () => {
  const fixture = makeManagedResourceFixture();
  const resources = { name: "resource-0", value: "value-0", bytes:
    makeDotNetResources([{ name: "resource-0", value: stringResourceValue("value-0") }]) };
  putPayload(fixture.bytes, fixture.resourceRva, resources.bytes);

  const parsed = await parseManagedResources(
    new MockFile(fixture.bytes),
    rva => rva,
    makeClr(fixture.resourceRva, [makeRow(generatedLabel("resources", 0), 0)], fixture.directorySize)
  );

  assert.strictEqual(parsed?.entries[0]?.entries?.[0]?.name, resources.name);
  assert.strictEqual(parsed?.entries[0]?.entries?.[0]?.type, "String");
  assert.strictEqual(parsed?.entries[0]?.entries?.[0]?.value, resources.value);
});

void test("parseManagedResources keeps external resources visible and reports invalid indexes", async () => {
  const fixture = makeManagedResourceFixture();
  const parsed = await parseManagedResources(
    new MockFile(fixture.bytes),
    rva => rva,
    makeClr(fixture.resourceRva, [
      makeRow(generatedLabel("external", 0), 0, {
        table: "File",
        tableId: CLR_FILE_TABLE_ID,
        row: 1,
        raw: 1,
        valid: true
      }),
      makeRow(generatedLabel("invalid-implementation", 0), 0, {
        table: "AssemblyRef",
        tableId: CLR_ASSEMBLY_REF_TABLE_ID,
        row: 0,
        raw: 1,
        tag: 1,
        valid: false
      })
    ], fixture.directorySize)
  );

  assert.strictEqual(parsed?.entries[0]?.storage, "external");
  assert.strictEqual(parsed?.entries[0]?.size, null);
  assert.strictEqual(parsed?.entries[1]?.storage, "unmapped");
  assert.ok(parsed?.issues.some(issue => issue.includes("invalid Implementation")));
});

void test("parseManagedResources reports truncated embedded payloads", async () => {
  const fixture = makeManagedResourceFixture();
  const bytes = new Uint8Array(fixture.resourceRva + Uint32Array.BYTES_PER_ELEMENT);
  new DataView(bytes.buffer).setUint32(fixture.resourceRva, Uint32Array.BYTES_PER_ELEMENT * 2, true);

  const parsed = await parseManagedResources(
    new MockFile(bytes),
    rva => rva,
    makeClr(fixture.resourceRva, [makeRow(generatedLabel("truncated", 0), 0)], fixture.directorySize)
  );

  assert.strictEqual(parsed?.entries[0]?.storage, "truncated");
});

void test("parseManagedResources bounds manifest offsets to the CLR Resources directory", async () => {
  const fixture = makeManagedResourceFixture();
  putPayload(
    fixture.bytes,
    fixture.resourceRva + fixture.directorySize,
    textEncoder.encode(generatedLabel("outside-payload", 0))
  );

  const parsed = await parseManagedResources(
    new MockFile(fixture.bytes),
    rva => rva,
    makeClr(fixture.resourceRva, [makeRow(generatedLabel("outside", 0), fixture.directorySize)], fixture.directorySize)
  );

  assert.strictEqual(parsed?.entries[0]?.storage, "truncated");
  assert.strictEqual(parsed?.entries[0]?.previewKind, undefined);
  assert.ok(parsed?.issues.some(issue => issue.includes("outside the CLR Resources directory")));
});

void test("parseManagedResources rejects payloads that exceed the CLR Resources directory", async () => {
  const fixture = makeManagedResourceFixture();
  const nearDirectoryEndOffset = fixture.directorySize - Uint32Array.BYTES_PER_ELEMENT * 4;
  putPayload(
    fixture.bytes,
    fixture.resourceRva + nearDirectoryEndOffset,
    textEncoder.encode(generatedLabel("oversized-payload", 0))
  );

  const parsed = await parseManagedResources(
    new MockFile(fixture.bytes),
    rva => rva,
    makeClr(fixture.resourceRva, [makeRow(generatedLabel("overflow", 0), nearDirectoryEndOffset)], fixture.directorySize)
  );

  assert.strictEqual(parsed?.entries[0]?.storage, "truncated");
  assert.ok(parsed?.issues.some(issue => issue.includes("payload extends past")));
});

void test("missing resource tables and directories produce no resource analysis", async () => {
  const parsed = await parseManagedResources(new MockFile(new Uint8Array()), () => null,
    makeClr(0, [], 0));

  assert.strictEqual(parsed, null);
});

void test("unmapped and truncated length prefixes have visible diagnostics", async () => {
  const fixture = makeManagedResourceFixture();

  const unmapped = await parseManagedResources(new MockFile(fixture.bytes), () => null,
    makeClr(fixture.resourceRva, [makeRow("unmapped", 0)], fixture.directorySize));
  const truncated = await parseManagedResources(new MockFile(new Uint8Array(2)), rva => rva,
    makeClr(0, [makeRow("truncated", 0)], fixture.directorySize));

  assert.strictEqual(unmapped?.entries[0]?.storage, "unmapped");
  assert.match(unmapped?.issues.join(" ") ?? "", /unmapped/);
  assert.strictEqual(truncated?.entries[0]?.storage, "truncated");
  assert.match(truncated?.issues.join(" ") ?? "", /prefix is truncated/);
});

void test("RVA overflow is rejected before file reads", async () => {
  const file = new MockFile(new Uint8Array());

  const parsed = await parseManagedResources(file, rva => rva,
    makeClr(0xffffffff, [makeRow("overflow", 4)], 16));

  assert.strictEqual(parsed?.entries[0]?.storage, "unmapped");
  assert.match(parsed?.issues.join(" ") ?? "", /overflows/);
});

void test("oversized payloads are not read merely to generate a preview", async context => {
  const file = new MockFile(new Uint8Array(4));
  new DataView(file.data.buffer).setUint32(0, 8 * 1024 * 1024 + 1, true);
  // MockFile's Blob stores a copy, so use its bounded reader as the source here.
  context.mock.method(file, "read", async () => new DataView(file.data.buffer));

  const parsed = await parseManagedResources(file, rva => rva,
    makeClr(0, [makeRow("large", 0)], 8 * 1024 * 1024 + 5));

  assert.strictEqual(parsed?.entries[0]?.storage, "embedded");
  assert.strictEqual(parsed?.entries[0]?.previewKind, undefined);
  assert.match(parsed?.issues.join(" ") ?? "", /preview is capped/);
});

void test("aliasing ManifestResource rows reuse payload reads without losing row identity", async context => {
  const fixture = makeManagedResourceFixture();
  putPayload(fixture.bytes, fixture.resourceRva, textEncoder.encode("text"));
  const file = new MockFile(fixture.bytes);
  const read = context.mock.method(file, "read");

  const parsed = await parseManagedResources(file, rva => rva,
    makeClr(fixture.resourceRva, [makeRow("first", 0), { ...makeRow("second", 0), row: 2 }],
      fixture.directorySize));

  assert.strictEqual(read.mock.callCount(), 2);
  assert.deepStrictEqual(parsed?.entries.map(entry => entry.name), ["first", "second"]);
  assert.deepStrictEqual(parsed?.entries.map(entry => entry.row), [1, 2]);
});
