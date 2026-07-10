"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseDwarfUnitHeader } from "../../../../analyzers/dwarf/unit-header.js";
import type { DwarfSectionInput } from "../../../../analyzers/dwarf/types.js";
import {
  TEST_DWARF,
  encodeDwarf32Unit,
  encodeDwarf64Unit,
  encodeDwarf5HeaderBody,
  encodeLegacyHeaderBody,
  encodeUint32,
  encodeUint64
} from "../../../fixtures/dwarf-fixture-encoding.js";
import { MockFile } from "../../../helpers/mock-file.js";

// Header bytes below encode the layouts in DWARF 5 sections 7.4 and 7.5.1:
// https://dwarfstd.org/doc/DWARF5.pdf

const parseHeader = async (
  bytes: number[],
  name = ".debug_info",
  issues: string[] = []
) => {
  const file = new MockFile(Uint8Array.from(bytes));
  const section: DwarfSectionInput = { name, offset: 0, size: bytes.length, compressed: false };
  return parseDwarfUnitHeader(file, section, 0, true, issues);
};

void test("parseDwarfUnitHeader parses 64-bit DWARF 5 type units", async () => {
  const bytes = encodeDwarf64Unit(encodeDwarf5HeaderBody(
    TEST_DWARF.unitType.type,
    TEST_DWARF.addressSize.x64,
    TEST_DWARF.sectionOffset.start,
    TEST_DWARF.format.dwarf64,
    encodeUint64(TEST_DWARF.sectionOffset.start),
    encodeUint64(TEST_DWARF.sectionOffset.start)
  ));

  const header = await parseHeader(bytes);

  assert.equal(header?.format, TEST_DWARF.format.dwarf64);
  assert.equal(header?.unitType, TEST_DWARF.unitType.type);
  assert.equal(header?.addressSize, TEST_DWARF.addressSize.x64);
  assert.equal(header?.dataOffset, bytes.length);
});

void test("parseDwarfUnitHeader parses legacy .debug_types headers", async () => {
  const bytes = encodeDwarf32Unit(encodeLegacyHeaderBody(
    TEST_DWARF.version.four,
    TEST_DWARF.addressSize.x64,
    TEST_DWARF.sectionOffset.start,
    encodeUint64(TEST_DWARF.sectionOffset.start),
    encodeUint32(TEST_DWARF.sectionOffset.start)
  ));

  const header = await parseHeader(bytes, ".debug_types");

  assert.equal(header?.unitType, TEST_DWARF.unitType.type);
  assert.equal(header?.version, TEST_DWARF.version.four);
  assert.equal(header?.dataOffset, bytes.length);
});

void test("parseDwarfUnitHeader rejects zero lengths, unsupported versions, and address sizes", async () => {
  const zeroIssues: string[] = [];
  const versionIssues: string[] = [];
  const addressIssues: string[] = [];

  assert.equal(await parseHeader(
    encodeUint32(TEST_DWARF.initialLength.zero),
    ".debug_info",
    zeroIssues
  ), null);
  assert.equal(await parseHeader(encodeDwarf32Unit(encodeLegacyHeaderBody(
    TEST_DWARF.invalid.version,
    TEST_DWARF.addressSize.x64,
    TEST_DWARF.sectionOffset.start
  )), ".debug_info", versionIssues), null);
  assert.equal(await parseHeader(encodeDwarf32Unit(encodeDwarf5HeaderBody(
    TEST_DWARF.unitType.compile,
    TEST_DWARF.invalid.addressSize,
    TEST_DWARF.sectionOffset.start,
    TEST_DWARF.format.dwarf32
  )), ".debug_info", addressIssues), null);
  assert.ok(zeroIssues[0]?.includes("zero-length"));
  assert.ok(versionIssues[0]?.includes("unsupported DWARF version"));
  assert.ok(addressIssues[0]?.includes("unsupported address size"));
});

void test("parseDwarfUnitHeader rejects unknown DWARF 5 unit types", async () => {
  const issues: string[] = [];

  const header = await parseHeader(
    encodeDwarf32Unit(encodeDwarf5HeaderBody(
      TEST_DWARF.invalid.unitType,
      TEST_DWARF.addressSize.x64,
      TEST_DWARF.sectionOffset.start,
      TEST_DWARF.format.dwarf32
    )),
    ".debug_info",
    issues
  );

  assert.equal(header, null);
  assert.ok(issues[0]?.includes(
    `unsupported unit type 0x${TEST_DWARF.invalid.unitType.toString(16)}`
  ));
});

void test("parseDwarfUnitHeader bounds units that extend beyond their section", async () => {
  const issues: string[] = [];
  const body = encodeLegacyHeaderBody(
    TEST_DWARF.version.four,
    TEST_DWARF.addressSize.x64,
    TEST_DWARF.sectionOffset.start
  );
  const header = await parseHeader(
    encodeDwarf32Unit(body, body.length + BigUint64Array.BYTES_PER_ELEMENT),
    ".debug_info",
    issues
  );

  assert.equal(header?.end, Uint32Array.BYTES_PER_ELEMENT + body.length);
  assert.ok(issues.some(issue => issue.includes("extends beyond")));
});
