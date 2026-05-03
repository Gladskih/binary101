"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseManagedResources } from "../../analyzers/pe/clr/managed-resources.js";
import type { PeClrHeader, PeClrManifestResourceInfo, PeClrMeta } from "../../analyzers/pe/clr/types.js";
import { createPngFile } from "../fixtures/image-sample-files.js";
import { MockFile } from "../helpers/mock-file.js";

const textEncoder = new TextEncoder();
// ResourceManager header: magic, header version, and header byte count fields.
const RESOURCE_MANAGER_FIXED_HEADER_SIZE = Uint32Array.BYTES_PER_ELEMENT * 3;
// RuntimeResourceSet header stores version, resource count, and type-name count.
const RUNTIME_RESOURCE_SET_FIXED_HEADER_SIZE = Uint32Array.BYTES_PER_ELEMENT * 3;
// ResourceReader aligns the runtime data after the type-name table to 8 bytes.
const RUNTIME_RESOURCE_SET_ALIGNMENT = 8;
// .resources constants come from System.Resources.ResourceReader/ResourceWriter in dotnet/runtime:
// https://github.com/dotnet/runtime/blob/main/src/libraries/System.Private.CoreLib/src/System/Resources/ResourceReader.cs
// https://github.com/dotnet/runtime/blob/main/src/libraries/System.Private.CoreLib/src/System/Resources/ResourceWriter.cs
const RESOURCE_MANAGER_MAGIC = 0xbeefcace;
const RESOURCE_MANAGER_VERSION = 1;
const RUNTIME_RESOURCE_SET_VERSION = 2;
const RESOURCE_TYPE_CODE_STRING = 1;
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

const writeSevenBitInt = (value: number): number[] => {
  const bytes: number[] = [];
  let remaining = value;
  do {
    let byte = remaining & 0x7f;
    remaining >>>= 7;
    if (remaining) byte |= 0x80;
    bytes.push(byte);
  } while (remaining);
  return bytes;
};

const binaryString = (value: string): number[] => {
  const bytes = textEncoder.encode(value);
  return [...writeSevenBitInt(bytes.length), ...bytes];
};

const utf16Name = (value: string): number[] => {
  const bytes = new Uint8Array(value.length * 2);
  const view = new DataView(bytes.buffer);
  for (let index = 0; index < value.length; index += 1) view.setUint16(index * 2, value.charCodeAt(index), true);
  return [...writeSevenBitInt(bytes.length), ...bytes];
};

const generatedLabel = (prefix: string, index: number): string => `${prefix}-${index.toString(36)}`;
const generatedTextPayload = (index: number): string => JSON.stringify({ value: generatedLabel("payload", index) });

const makeDotNetResources = (): { bytes: Uint8Array; name: string; value: string } => {
  const readerType = binaryString("System.Resources.ResourceReader");
  const setType = binaryString("System.Resources.RuntimeResourceSet");
  const resourceName = generatedLabel("resource", 0);
  const resourceValue = generatedLabel("value", 0);
  const name = utf16Name(resourceName);
  const value = [
    ...writeSevenBitInt(RESOURCE_TYPE_CODE_STRING),
    ...binaryString(resourceValue)
  ];
  const headerSize = readerType.length + setType.length;
  const runtimeHeaderOffset = RESOURCE_MANAGER_FIXED_HEADER_SIZE + headerSize;
  const alignedHeaderEnd =
    (runtimeHeaderOffset + RUNTIME_RESOURCE_SET_FIXED_HEADER_SIZE + RUNTIME_RESOURCE_SET_ALIGNMENT - 1) &
    ~(RUNTIME_RESOURCE_SET_ALIGNMENT - 1);
  const nameTableOffset = alignedHeaderEnd + RUNTIME_RESOURCE_SET_FIXED_HEADER_SIZE;
  const dataSectionOffset = nameTableOffset + name.length + 4;
  const bytes = new Uint8Array(dataSectionOffset + value.length);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, RESOURCE_MANAGER_MAGIC, true);
  view.setUint32(4, RESOURCE_MANAGER_VERSION, true);
  view.setUint32(8, headerSize, true);
  bytes.set(readerType, RESOURCE_MANAGER_FIXED_HEADER_SIZE);
  bytes.set(setType, RESOURCE_MANAGER_FIXED_HEADER_SIZE + readerType.length);
  view.setUint32(runtimeHeaderOffset, RUNTIME_RESOURCE_SET_VERSION, true);
  view.setInt32(runtimeHeaderOffset + 4, 1, true);
  view.setInt32(runtimeHeaderOffset + 8, 0, true);
  view.setUint32(alignedHeaderEnd, bytes.byteLength, true);
  view.setUint32(alignedHeaderEnd + 4, 0, true);
  view.setUint32(alignedHeaderEnd + 8, dataSectionOffset, true);
  bytes.set(name, nameTableOffset);
  view.setUint32(nameTableOffset + name.length, 0, true);
  bytes.set(value, dataSectionOffset);
  return { bytes, name: resourceName, value: resourceValue };
};

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
  const resources = makeDotNetResources();
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
