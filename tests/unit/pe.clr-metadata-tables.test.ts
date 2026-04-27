"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseClrDirectory } from "../../analyzers/pe/clr/index.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";

// ECMA-335 II.25.3.3: IMAGE_COR20_HEADER is 0x48 bytes.
const IMAGE_COR20_HEADER_SIZE = 0x48;
const CLR_DIRECTORY_RVA = 0x100;
const METADATA_RVA = 0x200;
const FIXTURE_FILE_SIZE = 0x500;
const DECLARED_METADATA_SIZE = 0x200;
const TABLE_STREAM_OFFSET = 0x80;
// ECMA-335 II.24.2.1: metadata root signature "BSJB" = 0x424A5342.
const CLR_METADATA_ROOT_SIGNATURE = 0x424a5342;
const CLR_METADATA_TABLE_STREAM_MAJOR_VERSION = 2;
const CLR_METADATA_TABLE_STREAM_MINOR_VERSION = 0;
const CLR_METADATA_TABLE_STREAM_RESERVED2 = 1;
const CLR_METADATA_STREAM_COUNT = 3;
// ECMA-335 II.24.2.6 Valid mask table ids used by this fixture.
const TABLE_MODULE = 0x00;
const TABLE_TYPE_REF = 0x01;
const TABLE_MEMBER_REF = 0x0a;
const TABLE_CUSTOM_ATTRIBUTE = 0x0c;
const TABLE_ASSEMBLY = 0x20;
// ECMA-335 II.22.1.1 AssemblyHashAlgorithm: 0x8004 is SHA1.
const ASSEMBLY_HASH_ALGORITHM_SHA1 = 0x00008004;
// ECMA-335 II.25.3.3.1 COMIMAGE_FLAGS_ILONLY.
const COMIMAGE_FLAGS_ILONLY = 0x00000001;
const METHOD_SIGNATURE_HASTHIS = 0x20; // ECMA-335 II.23.2.1 HASTHIS calling-convention bit.
const ELEMENT_TYPE_VOID = 0x01; // ECMA-335 II.23.1.16 ELEMENT_TYPE_VOID.
const ELEMENT_TYPE_STRING = 0x0e; // ECMA-335 II.23.1.16 ELEMENT_TYPE_STRING.
const PROPERTY_NAMED_ARGUMENT = 0x54; // ECMA-335 II.23.3 PROPERTY named argument tag.

const encoder = new TextEncoder();
const align4 = (value: number): number => (value + 3) & ~3;
const rvaToOff = (rva: number): number => rva;
const tableMask = (...tableIds: number[]): number =>
  tableIds.reduce((mask, tableId) => mask | (1 << tableId), 0);

const addString = (heap: number[], text: string): number => {
  const index = heap.length;
  heap.push(...encoder.encode(text), 0);
  return index;
};

const addBlob = (heap: number[], bytes: number[]): number => {
  const index = heap.length;
  assert.ok(bytes.length < 0x80);
  heap.push(bytes.length, ...bytes);
  return index;
};

const serString = (text: string): number[] => {
  const bytes = [...encoder.encode(text)];
  assert.ok(bytes.length < 0x80);
  return [bytes.length, ...bytes];
};

const writeU16 = (bytes: number[], value: number): void => {
  bytes.push(value & 0xff, (value >>> 8) & 0xff);
};

const writeU32 = (bytes: number[], value: number): void => {
  bytes.push(value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff);
};

interface MetadataStringIndexes {
  module: number;
  assembly: number;
  attributeNamespace: number;
  attributeName: number;
  ctor: number;
}

interface MetadataBlobIndexes {
  ctorSignature: number;
  targetFrameworkAttribute: number;
}

interface MetadataStreamPlacement {
  offset: number;
  size: number;
  name: string;
}

const stringConstructorSignature = (): number[] => [
  METHOD_SIGNATURE_HASTHIS,
  1,
  ELEMENT_TYPE_VOID,
  ELEMENT_TYPE_STRING
];

const targetFrameworkAttributeBlob = (): number[] => [
  0x01, 0x00,
  ...serString(".NETCoreApp,Version=v8.0"),
  0x01, 0x00,
  PROPERTY_NAMED_ARGUMENT,
  ELEMENT_TYPE_STRING,
  ...serString("FrameworkDisplayName"),
  ...serString(".NET 8.0")
];

const createMetadataTableStream = (
  strings: MetadataStringIndexes,
  blobs: MetadataBlobIndexes
): Uint8Array => {
  const bytes: number[] = [];
  writeU32(bytes, 0);
  bytes.push(
    CLR_METADATA_TABLE_STREAM_MAJOR_VERSION,
    CLR_METADATA_TABLE_STREAM_MINOR_VERSION,
    0,
    CLR_METADATA_TABLE_STREAM_RESERVED2
  );
  writeU32(bytes, tableMask(TABLE_MODULE, TABLE_TYPE_REF, TABLE_MEMBER_REF, TABLE_CUSTOM_ATTRIBUTE));
  writeU32(bytes, 1);
  writeU32(bytes, 0);
  writeU32(bytes, 0);
  // Row counts are stored in ascending table-id order for the five present tables.
  [1, 1, 1, 1, 1].forEach(count => writeU32(bytes, count));
  writeU16(bytes, 0);
  writeU16(bytes, strings.module);
  writeU16(bytes, 0);
  writeU16(bytes, 0);
  writeU16(bytes, 0);
  writeU16(bytes, 0);
  writeU16(bytes, strings.attributeName);
  writeU16(bytes, strings.attributeNamespace);
  writeU16(bytes, (1 << 3) | 1);
  writeU16(bytes, strings.ctor);
  writeU16(bytes, blobs.ctorSignature);
  writeU16(bytes, (1 << 5) | TABLE_ASSEMBLY);
  writeU16(bytes, (1 << 3) | 3);
  writeU16(bytes, blobs.targetFrameworkAttribute);
  writeU32(bytes, ASSEMBLY_HASH_ALGORITHM_SHA1);
  [1, 2, 3, 4].forEach(part => writeU16(bytes, part));
  writeU32(bytes, 0);
  writeU16(bytes, 0);
  writeU16(bytes, strings.assembly);
  writeU16(bytes, 0);
  return Uint8Array.from(bytes);
};

const createClrFileWithMetadataTables = (): MockFile => {
  const stringHeap = [0];
  const strings = {
    module: addString(stringHeap, "TestApp.dll"),
    assembly: addString(stringHeap, "TestApp"),
    attributeNamespace: addString(stringHeap, "System.Runtime.Versioning"),
    attributeName: addString(stringHeap, "TargetFrameworkAttribute"),
    ctor: addString(stringHeap, ".ctor")
  };
  const blobHeap = [0];
  const blobs = {
    ctorSignature: addBlob(blobHeap, stringConstructorSignature()),
    targetFrameworkAttribute: addBlob(blobHeap, targetFrameworkAttributeBlob())
  };
  const tableStream = createMetadataTableStream(strings, blobs);
  const bytes = new Uint8Array(FIXTURE_FILE_SIZE).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint32(CLR_DIRECTORY_RVA, IMAGE_COR20_HEADER_SIZE, true);
  view.setUint16(CLR_DIRECTORY_RVA + 4, 4, true);
  view.setUint32(CLR_DIRECTORY_RVA + 8, METADATA_RVA, true);
  view.setUint32(CLR_DIRECTORY_RVA + 12, DECLARED_METADATA_SIZE, true);
  view.setUint32(CLR_DIRECTORY_RVA + 16, COMIMAGE_FLAGS_ILONLY, true);
  let cursor = METADATA_RVA;
  view.setUint32(cursor, CLR_METADATA_ROOT_SIGNATURE, true);
  view.setUint16(cursor + 4, 1, true);
  view.setUint16(cursor + 6, 1, true);
  view.setUint32(cursor + 12, 12, true);
  bytes.set(encoder.encode("v4.0.30319\0"), cursor + 16);
  cursor += 28;
  view.setUint16(cursor, 0, true);
  view.setUint16(cursor + 2, CLR_METADATA_STREAM_COUNT, true);
  cursor += 4;
  const stringsOffset = TABLE_STREAM_OFFSET + align4(tableStream.length);
  const blobOffset = stringsOffset + align4(stringHeap.length);
  const streams: MetadataStreamPlacement[] = [
    { offset: TABLE_STREAM_OFFSET, size: tableStream.length, name: "#~" },
    { offset: stringsOffset, size: stringHeap.length, name: "#Strings" },
    { offset: blobOffset, size: blobHeap.length, name: "#Blob" }
  ];
  streams.forEach(stream => {
    view.setUint32(cursor, stream.offset, true);
    view.setUint32(cursor + 4, stream.size, true);
    bytes.set(encoder.encode(`${stream.name}\0`), cursor + 8);
    cursor += 8 + align4(stream.name.length + 1);
  });
  bytes.set(tableStream, METADATA_RVA + TABLE_STREAM_OFFSET);
  bytes.set(Uint8Array.from(stringHeap), METADATA_RVA + stringsOffset);
  bytes.set(Uint8Array.from(blobHeap), METADATA_RVA + blobOffset);
  return new MockFile(bytes, "managed.bin");
};

void test("parseClrDirectory decodes ECMA-335 metadata tables and TargetFrameworkAttribute", async () => {
  const clr = await parseClrDirectory(
    createClrFileWithMetadataTables(),
    [{ name: "CLR_RUNTIME", rva: CLR_DIRECTORY_RVA, size: IMAGE_COR20_HEADER_SIZE }],
    rvaToOff
  );
  const metadata = expectDefined(expectDefined(expectDefined(clr).meta).tables);
  const targetFramework = expectDefined(metadata.customAttributes[0]);

  assert.strictEqual(metadata.assembly?.name, "TestApp");
  assert.strictEqual(metadata.assembly?.version, "1.2.3.4");
  assert.strictEqual(metadata.typeRefs[0]?.fullName, "System.Runtime.Versioning.TargetFrameworkAttribute");
  assert.strictEqual(targetFramework.attributeType, "System.Runtime.Versioning.TargetFrameworkAttribute");
  assert.strictEqual(targetFramework.fixedArguments[0]?.value, ".NETCoreApp,Version=v8.0");
  assert.strictEqual(targetFramework.namedArguments[0]?.value, ".NET 8.0");
});
