"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseReadyToRun } from "../../analyzers/pe/clr/ready-to-run.js";
import type { PeClrHeader } from "../../analyzers/pe/clr/types.js";
import { MockFile } from "../helpers/mock-file.js";

type ReadyToRunFixture = {
  bytes: Uint8Array;
  clr: PeClrHeader;
  layout: {
    headerRva: number;
    coreHeaderSize: number;
    declaredHeaderSize: number;
    signature: number;
    strippedIlBodies: number;
  };
};

type ReadyToRunSectionSpec = {
  type: number;
  rva: number;
  size: number;
};

// Values below are copied from dotnet/runtime src/coreclr/inc/readytorun.h:
// https://github.com/dotnet/runtime/blob/main/src/coreclr/inc/readytorun.h
const READY_TO_RUN_SIGNATURE = 0x00525452;
const READY_TO_RUN_MAJOR_VERSION = 18;
const READY_TO_RUN_STRIPPED_IL_BODIES = 0x00000200;
const COMPILER_IDENTIFIER_SECTION = 100;
const OWNER_COMPOSITE_EXECUTABLE_SECTION = 116;
// CoreCLR corcompile.h defines CORCOMPILE_SIGNATURE for NGen CORCOMPILE_HEADER.
// https://raw.githubusercontent.com/dotnet/coreclr/master/src/inc/corcompile.h
const NGEN_SIGNATURE = 0x0045474e;

const makeClr = (rva: number, size: number): PeClrHeader => ({
  cb: 0x48, // ECMA-335 II.25.3.3 IMAGE_COR20_HEADER byte size.
  MajorRuntimeVersion: 4,
  MinorRuntimeVersion: 0,
  MetaDataRVA: 0,
  MetaDataSize: 0,
  Flags: 0,
  EntryPointToken: 0,
  ResourcesRVA: 0,
  ResourcesSize: 0,
  StrongNameSignatureRVA: 0,
  StrongNameSignatureSize: 0,
  CodeManagerTableRVA: 0,
  CodeManagerTableSize: 0,
  VTableFixupsRVA: 0,
  VTableFixupsSize: 0,
  ExportAddressTableJumpsRVA: 0,
  ExportAddressTableJumpsSize: 0,
  ManagedNativeHeaderRVA: rva,
  ManagedNativeHeaderSize: size
});

const writeSection = (view: DataView, cursor: { offset: number }, section: ReadyToRunSectionSpec): void => {
  view.setUint32(cursor.offset, section.type, true);
  view.setUint32(cursor.offset + Uint32Array.BYTES_PER_ELEMENT, section.rva, true);
  view.setUint32(cursor.offset + Uint32Array.BYTES_PER_ELEMENT * 2, section.size, true);
  cursor.offset += Uint32Array.BYTES_PER_ELEMENT * 3;
};

const makeReadyToRunFixture = (sections: ReadyToRunSectionSpec[] = []): ReadyToRunFixture => {
  const coreHeaderSize = Uint32Array.BYTES_PER_ELEMENT * 4;
  const sectionEntrySize = Uint32Array.BYTES_PER_ELEMENT * 3;
  const declaredHeaderSize = coreHeaderSize + sectionEntrySize * sections.length;
  const headerRva = declaredHeaderSize;
  const bytes = new Uint8Array(headerRva + declaredHeaderSize);
  const view = new DataView(bytes.buffer);
  view.setUint32(headerRva, READY_TO_RUN_SIGNATURE, true);
  view.setUint16(headerRva + Uint32Array.BYTES_PER_ELEMENT, READY_TO_RUN_MAJOR_VERSION, true);
  view.setUint16(headerRva + Uint32Array.BYTES_PER_ELEMENT + Uint16Array.BYTES_PER_ELEMENT, 5, true);
  view.setUint32(headerRva + Uint32Array.BYTES_PER_ELEMENT * 2, READY_TO_RUN_STRIPPED_IL_BODIES, true);
  view.setUint32(headerRva + Uint32Array.BYTES_PER_ELEMENT * 3, sections.length, true);
  const cursor = { offset: headerRva + coreHeaderSize };
  sections.forEach(section => writeSection(view, cursor, section));
  return {
    bytes,
    clr: makeClr(headerRva, declaredHeaderSize),
    layout: {
      headerRva,
      coreHeaderSize,
      declaredHeaderSize,
      signature: READY_TO_RUN_SIGNATURE,
      strippedIlBodies: READY_TO_RUN_STRIPPED_IL_BODIES
    }
  };
};

void test("parseReadyToRun parses RTR headers and named section entries", async () => {
  const fixture = makeReadyToRunFixture([
    {
      type: COMPILER_IDENTIFIER_SECTION,
      rva: READY_TO_RUN_SIGNATURE + Uint32Array.BYTES_PER_ELEMENT,
      size: READY_TO_RUN_MAJOR_VERSION
    },
    {
      type: OWNER_COMPOSITE_EXECUTABLE_SECTION,
      rva: READY_TO_RUN_SIGNATURE + Uint32Array.BYTES_PER_ELEMENT * 2,
      size: READY_TO_RUN_MAJOR_VERSION + Uint32Array.BYTES_PER_ELEMENT
    }
  ]);

  const parsed = await parseReadyToRun(new MockFile(fixture.bytes), rva => rva, fixture.clr);

  assert.strictEqual(parsed.status, "ready-to-run");
  assert.strictEqual(parsed.majorVersion, READY_TO_RUN_MAJOR_VERSION);
  assert.strictEqual(parsed.flags, READY_TO_RUN_STRIPPED_IL_BODIES);
  assert.deepStrictEqual(parsed.sections.map(section => section.name), ["CompilerIdentifier", "OwnerCompositeExecutable"]);
});

void test("parseReadyToRun reports non-RTR managed native headers", async () => {
  const fixture = makeReadyToRunFixture();
  const view = new DataView(fixture.bytes.buffer);
  const nonReadyToRunSignature = READY_TO_RUN_SIGNATURE ^ READY_TO_RUN_STRIPPED_IL_BODIES;
  view.setUint32(fixture.layout.headerRva, nonReadyToRunSignature, true);

  const parsed = await parseReadyToRun(new MockFile(fixture.bytes), rva => rva, fixture.clr);

  assert.strictEqual(parsed.status, "unknown-managed-native-header");
  assert.strictEqual(parsed.signature, nonReadyToRunSignature);
  assert.strictEqual(parsed.majorVersion, null);
  assert.strictEqual(parsed.flags, null);
  assert.deepStrictEqual(parsed.issues, []);
});

void test("parseReadyToRun recognizes NGen managed native headers", async () => {
  const fixture = makeReadyToRunFixture();
  const view = new DataView(fixture.bytes.buffer);
  view.setUint32(fixture.layout.headerRva, NGEN_SIGNATURE, true);

  const parsed = await parseReadyToRun(new MockFile(fixture.bytes), rva => rva, fixture.clr);

  assert.strictEqual(parsed.status, "ngen");
  assert.strictEqual(parsed.signature, NGEN_SIGNATURE);
  assert.strictEqual(parsed.majorVersion, null);
  assert.strictEqual(parsed.flags, null);
  assert.strictEqual(parsed.sectionCount, 0);
  assert.deepStrictEqual(parsed.sections, []);
  assert.deepStrictEqual(parsed.issues, []);
});

void test("parseReadyToRun reports truncated section tables", async () => {
  const fixture = makeReadyToRunFixture([{ type: COMPILER_IDENTIFIER_SECTION, rva: 0, size: 0 }]);
  const bytes = fixture.bytes.subarray(0, fixture.layout.headerRva + fixture.layout.coreHeaderSize);

  const parsed = await parseReadyToRun(new MockFile(bytes), rva => rva, fixture.clr);

  assert.strictEqual(parsed.status, "ready-to-run");
  assert.ok(parsed.issues.some(issue => issue.includes("truncated")));
});

void test("parseReadyToRun does not read sections past ManagedNativeHeaderSize", async () => {
  const fixture = makeReadyToRunFixture([{ type: COMPILER_IDENTIFIER_SECTION, rva: 0, size: 0 }]);
  const clr = makeClr(fixture.layout.headerRva, fixture.layout.coreHeaderSize);

  const parsed = await parseReadyToRun(new MockFile(fixture.bytes), rva => rva, clr);

  assert.strictEqual(parsed.status, "ready-to-run");
  assert.deepStrictEqual(parsed.sections, []);
  assert.ok(parsed.issues.some(issue => issue.includes("truncated")));
});

void test("parseReadyToRun reports absent and unmapped headers", async () => {
  const fixture = makeReadyToRunFixture();
  const absent = await parseReadyToRun(new MockFile(fixture.bytes), rva => rva, makeClr(0, 0));
  const unmapped = await parseReadyToRun(new MockFile(fixture.bytes), () => null, fixture.clr);

  assert.strictEqual(absent.status, "absent");
  assert.strictEqual(unmapped.status, "unmapped");
});
