"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  COFF_FILE_CHARACTERISTICS,
  COFF_FILE_HEADER_BYTE_LENGTH,
  COFF_FILE_HEADER_FIELDS,
  COFF_SECTION_HEADER_BYTE_LENGTH,
  COFF_SECTION_HEADER_FIELDS,
  COFF_SHORT_NAME_BYTE_LENGTH,
  type CoffNumericField
} from "../../../../analyzers/coff/layout.js";
import { IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_UNKNOWN } from "../../../../analyzers/coff/machine.js";
import { buildCoffObjectLabel, probeCoffObject } from "../../../../analyzers/coff/probe.js";
import { createCoffObjectBytes } from "../../../fixtures/coff-object-fixture.js";

const writeField = (view: DataView, base: number, field: CoffNumericField, value: number): void => {
  const offset = base + field.offset;
  if (field.width === "u8") view.setUint8(offset, value);
  else if (field.width === "u16") view.setUint16(offset, value, true);
  else if (field.width === "i16") view.setInt16(offset, value, true);
  else view.setUint32(offset, value, true);
};

const createProbeBytes = (): Uint8Array => createCoffObjectBytes().slice();

// Project detection reads a 64 KiB probe window; Microsoft PE/COFF places the
// section table after the 20-byte file header.
const PROBE_SECTION_DETECTION_COUNT_LIMIT = Math.floor(
  ((64 * 1024) - COFF_FILE_HEADER_BYTE_LENGTH) / COFF_SECTION_HEADER_BYTE_LENGTH
);

const createMinimalProbeBytes = (sectionCount: number, byteLength: number): Uint8Array => {
  const bytes = new Uint8Array(byteLength);
  const view = new DataView(bytes.buffer);
  writeField(view, 0, COFF_FILE_HEADER_FIELDS.Machine, IMAGE_FILE_MACHINE_I386);
  writeField(view, 0, COFF_FILE_HEADER_FIELDS.NumberOfSections, sectionCount);
  return bytes;
};

const probe = (bytes: Uint8Array, fileSize = bytes.length) =>
  probeCoffObject(new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength), fileSize);

void test("probeCoffObject accepts plausible COFF objects and labels the machine", () => {
  const result = probe(createProbeBytes());

  assert.deepEqual(result, { machine: IMAGE_FILE_MACHINE_I386 });
  assert.equal(buildCoffObjectLabel(result!), "COFF object file for x86 (I386)");
});

void test("probeCoffObject rejects malformed COFF file headers", () => {
  const optional = createProbeBytes();
  const executable = createProbeBytes();
  const dll = createProbeBytes();
  const noSections = createProbeBytes();
  const tooManySections = createProbeBytes();
  const unknownMachine = createProbeBytes();
  const optionalView = new DataView(optional.buffer);
  writeField(optionalView, 0, COFF_FILE_HEADER_FIELDS.SizeOfOptionalHeader, 1);
  writeField(
    new DataView(executable.buffer),
    0,
    COFF_FILE_HEADER_FIELDS.Characteristics,
    COFF_FILE_CHARACTERISTICS.EXECUTABLE_IMAGE
  );
  writeField(new DataView(dll.buffer), 0, COFF_FILE_HEADER_FIELDS.Characteristics, COFF_FILE_CHARACTERISTICS.DLL);
  writeField(new DataView(noSections.buffer), 0, COFF_FILE_HEADER_FIELDS.NumberOfSections, 0);
  writeField(
    new DataView(tooManySections.buffer),
    0,
    COFF_FILE_HEADER_FIELDS.NumberOfSections,
    PROBE_SECTION_DETECTION_COUNT_LIMIT + 1
  );
  writeField(new DataView(unknownMachine.buffer), 0, COFF_FILE_HEADER_FIELDS.Machine, IMAGE_FILE_MACHINE_UNKNOWN);

  assert.equal(probe(new Uint8Array(COFF_FILE_HEADER_BYTE_LENGTH - 1)), null);
  assert.equal(probe(optional), null);
  assert.equal(probe(executable), null);
  assert.equal(probe(dll), null);
  assert.equal(probe(noSections), null);
  assert.equal(probe(tooManySections), null);
  assert.equal(probe(unknownMachine), null);
});

void test("probeCoffObject rejects implausible section tables", () => {
  const truncatedTable = createProbeBytes();
  const blankName = createProbeBytes();
  const nonPrintableName = createProbeBytes();
  const tooHighNameByte = createProbeBytes();
  writeField(new DataView(truncatedTable.buffer), 0, COFF_FILE_HEADER_FIELDS.NumberOfSections, 2);
  blankName.fill(0, COFF_FILE_HEADER_BYTE_LENGTH, COFF_FILE_HEADER_BYTE_LENGTH + COFF_SHORT_NAME_BYTE_LENGTH);
  nonPrintableName[COFF_FILE_HEADER_BYTE_LENGTH] = 0x1f;
  tooHighNameByte[COFF_FILE_HEADER_BYTE_LENGTH] = 0x7f;

  assert.equal(probe(truncatedTable), null);
  assert.equal(probe(blankName), null);
  assert.equal(probe(nonPrintableName), null);
  assert.equal(probe(tooHighNameByte), null);
});

void test("probeCoffObject requires the declared section table to fit", () => {
  const shortSingleSection = createMinimalProbeBytes(
    1,
    COFF_FILE_HEADER_BYTE_LENGTH + COFF_SECTION_HEADER_BYTE_LENGTH - 1
  );
  const shortSecondSection = createMinimalProbeBytes(
    2,
    COFF_FILE_HEADER_BYTE_LENGTH + COFF_SECTION_HEADER_BYTE_LENGTH
  );
  shortSingleSection[COFF_FILE_HEADER_BYTE_LENGTH] = 0x41;
  shortSecondSection[COFF_FILE_HEADER_BYTE_LENGTH] = 0x41;

  assert.equal(probe(shortSingleSection), null);
  assert.equal(probe(shortSecondSection), null);
});

void test("probeCoffObject does not scan section names beyond the declared table", () => {
  const bytes = createMinimalProbeBytes(
    1,
    COFF_FILE_HEADER_BYTE_LENGTH + COFF_SECTION_HEADER_BYTE_LENGTH * 2
  );
  const secondSection = COFF_FILE_HEADER_BYTE_LENGTH + COFF_SECTION_HEADER_BYTE_LENGTH;
  bytes[secondSection] = 0x41;

  assert.equal(probe(bytes), null);
});

void test("probeCoffObject accepts printable section-name boundary bytes only inside the name", () => {
  const boundary = createProbeBytes();
  const afterNameNonPrintable = createProbeBytes();
  boundary.fill(0, COFF_FILE_HEADER_BYTE_LENGTH, COFF_FILE_HEADER_BYTE_LENGTH + COFF_SHORT_NAME_BYTE_LENGTH);
  boundary[COFF_FILE_HEADER_BYTE_LENGTH] = 0x20;
  boundary[COFF_FILE_HEADER_BYTE_LENGTH + 1] = 0x7e;
  afterNameNonPrintable.fill(
    0x41,
    COFF_FILE_HEADER_BYTE_LENGTH,
    COFF_FILE_HEADER_BYTE_LENGTH + COFF_SHORT_NAME_BYTE_LENGTH
  );
  afterNameNonPrintable[COFF_FILE_HEADER_BYTE_LENGTH + COFF_SHORT_NAME_BYTE_LENGTH] = 0x1f;
  afterNameNonPrintable[COFF_FILE_HEADER_BYTE_LENGTH - 1] = 0x1f;

  assert.deepEqual(probe(boundary), { machine: IMAGE_FILE_MACHINE_I386 });
  assert.deepEqual(probe(afterNameNonPrintable), { machine: IMAGE_FILE_MACHINE_I386 });
});

void test("probeCoffObject rejects implausible symbol table metadata", () => {
  const sectionTableEnd = COFF_FILE_HEADER_BYTE_LENGTH + COFF_SECTION_HEADER_BYTE_LENGTH;
  const beforeSections = createProbeBytes();
  const missingPointer = createProbeBytes();
  const zeroCount = createProbeBytes();
  const pastFile = createProbeBytes();
  writeField(new DataView(beforeSections.buffer), 0, COFF_FILE_HEADER_FIELDS.PointerToSymbolTable, sectionTableEnd - 1);
  writeField(new DataView(beforeSections.buffer), 0, COFF_FILE_HEADER_FIELDS.NumberOfSymbols, 1);
  writeField(new DataView(missingPointer.buffer), 0, COFF_FILE_HEADER_FIELDS.PointerToSymbolTable, 0);
  writeField(new DataView(missingPointer.buffer), 0, COFF_FILE_HEADER_FIELDS.NumberOfSymbols, 1);
  writeField(new DataView(zeroCount.buffer), 0, COFF_FILE_HEADER_FIELDS.PointerToSymbolTable, sectionTableEnd);
  writeField(new DataView(zeroCount.buffer), 0, COFF_FILE_HEADER_FIELDS.NumberOfSymbols, 0);
  writeField(new DataView(pastFile.buffer), 0, COFF_FILE_HEADER_FIELDS.PointerToSymbolTable, pastFile.length + 1);
  writeField(new DataView(pastFile.buffer), 0, COFF_FILE_HEADER_FIELDS.NumberOfSymbols, 1);

  assert.equal(probe(beforeSections), null);
  assert.equal(probe(missingPointer), null);
  assert.equal(probe(zeroCount), null);
  assert.equal(probe(pastFile), null);
});

void test("probeCoffObject accepts objects with no COFF symbol table", () => {
  const bytes = createMinimalProbeBytes(
    1,
    COFF_FILE_HEADER_BYTE_LENGTH + COFF_SECTION_HEADER_BYTE_LENGTH
  );
  bytes[COFF_FILE_HEADER_BYTE_LENGTH] = 0x41;

  assert.deepEqual(probe(bytes), { machine: IMAGE_FILE_MACHINE_I386 });
});

void test("probeCoffObject accepts boundary symbol table positions", () => {
  const sectionTableEnd = COFF_FILE_HEADER_BYTE_LENGTH + COFF_SECTION_HEADER_BYTE_LENGTH;
  const atSectionEnd = createProbeBytes();
  const atFileEnd = createProbeBytes();
  atSectionEnd[COFF_FILE_HEADER_BYTE_LENGTH] = 0x41;
  writeField(new DataView(atSectionEnd.buffer), 0, COFF_FILE_HEADER_FIELDS.PointerToSymbolTable, sectionTableEnd);
  writeField(new DataView(atSectionEnd.buffer), 0, COFF_FILE_HEADER_FIELDS.NumberOfSymbols, 1);
  writeField(new DataView(atFileEnd.buffer), 0, COFF_FILE_HEADER_FIELDS.PointerToSymbolTable, atFileEnd.length);
  writeField(new DataView(atFileEnd.buffer), 0, COFF_FILE_HEADER_FIELDS.NumberOfSymbols, 1);

  assert.deepEqual(probe(atSectionEnd), { machine: IMAGE_FILE_MACHINE_I386 });
  assert.deepEqual(probe(atFileEnd), { machine: IMAGE_FILE_MACHINE_I386 });
});

void test("probeCoffObject accepts the largest section table contained in the probe", () => {
  const bytes = new Uint8Array(
    COFF_FILE_HEADER_BYTE_LENGTH + COFF_SECTION_HEADER_BYTE_LENGTH * PROBE_SECTION_DETECTION_COUNT_LIMIT
  );
  const view = new DataView(bytes.buffer);
  writeField(view, 0, COFF_FILE_HEADER_FIELDS.Machine, IMAGE_FILE_MACHINE_I386);
  writeField(view, 0, COFF_FILE_HEADER_FIELDS.NumberOfSections, PROBE_SECTION_DETECTION_COUNT_LIMIT);
  const finalSection = COFF_FILE_HEADER_BYTE_LENGTH +
    COFF_SECTION_HEADER_BYTE_LENGTH * (PROBE_SECTION_DETECTION_COUNT_LIMIT - 1);
  bytes[finalSection] = 0x41;

  assert.deepEqual(probe(bytes), { machine: IMAGE_FILE_MACHINE_I386 });
});

void test("probeCoffObject accepts a partial large section table when it fits the file", () => {
  const sectionCount = PROBE_SECTION_DETECTION_COUNT_LIMIT + 1;
  const bytes = new Uint8Array(COFF_FILE_HEADER_BYTE_LENGTH + COFF_SECTION_HEADER_BYTE_LENGTH);
  const view = new DataView(bytes.buffer);
  writeField(view, 0, COFF_FILE_HEADER_FIELDS.Machine, IMAGE_FILE_MACHINE_I386);
  writeField(view, 0, COFF_FILE_HEADER_FIELDS.NumberOfSections, sectionCount);
  bytes[COFF_FILE_HEADER_BYTE_LENGTH] = 0x41;

  assert.deepEqual(
    probe(bytes, COFF_FILE_HEADER_BYTE_LENGTH + COFF_SECTION_HEADER_BYTE_LENGTH * sectionCount),
    { machine: IMAGE_FILE_MACHINE_I386 }
  );
});

void test("probeCoffObject scans beyond the first section for a printable section name", () => {
  const bytes = new Uint8Array(COFF_FILE_HEADER_BYTE_LENGTH + COFF_SECTION_HEADER_BYTE_LENGTH * 2);
  const view = new DataView(bytes.buffer);
  writeField(view, 0, COFF_FILE_HEADER_FIELDS.Machine, IMAGE_FILE_MACHINE_I386);
  writeField(view, 0, COFF_FILE_HEADER_FIELDS.NumberOfSections, 2);
  const secondSection = COFF_FILE_HEADER_BYTE_LENGTH + COFF_SECTION_HEADER_BYTE_LENGTH;
  bytes.set(Uint8Array.from([0x2e, 0x74, 0x78, 0x74]), secondSection);
  writeField(view, secondSection, COFF_SECTION_HEADER_FIELDS.PointerToRawData, bytes.length);

  assert.deepEqual(probe(bytes), { machine: IMAGE_FILE_MACHINE_I386 });
});
