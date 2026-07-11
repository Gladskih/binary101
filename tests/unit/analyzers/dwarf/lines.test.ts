"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzeDwarf } from "../../../../analyzers/dwarf/index.js";
import {
  TEST_DWARF,
  concatenateBytes,
  encodeCString,
  encodeUint8,
  encodeUint16,
  encodeUint32,
  encodeUint64,
  encodeUleb,
  withDwarf32InitialLength
} from "../../../fixtures/dwarf-fixture-encoding.js";
import {
  createDwarf4LineSectionWithProgram,
  createDwarf4LineSectionWithFileCount,
  createDwarf5LineSection,
  createDwarf2LineSection,
  createDwarf64LineSection,
  encodeLineAdvance,
  encodeLineExtended,
  encodeLineSpecial
} from "../../../fixtures/dwarf-line-fixture.js";
import { MockFile } from "../../../helpers/mock-file.js";

const analyzeLineSection = async (bytes: number[] | Uint8Array) => {
  const data = Uint8Array.from(bytes);
  return analyzeDwarf(new MockFile(data), [{
    name: ".debug_line",
    offset: TEST_DWARF.sectionOffset.start,
    size: data.length,
    compressed: false
  }], true);
};

const encodeOperandOpcode = (opcode: number, operand: bigint | number): number[] =>
  concatenateBytes(encodeUint8(opcode), encodeUleb(operand));

const createBroadOpcodeProgram = (): number[] => concatenateBytes(
  encodeLineExtended(
    TEST_DWARF.line.extendedOpcode.setAddress,
    encodeUint64(TEST_DWARF.line.address)
  ),
  encodeLineAdvance(TEST_DWARF.line.lineAdvance.previous),
  encodeOperandOpcode(
    TEST_DWARF.line.standardOpcode.setFile,
    TEST_DWARF.line.directoryIndex.legacyFirst
  ),
  encodeOperandOpcode(TEST_DWARF.line.standardOpcode.setColumn, TEST_DWARF.line.discriminator),
  encodeUint8(TEST_DWARF.line.standardOpcode.negateStatement),
  encodeUint8(TEST_DWARF.line.standardOpcode.setBasicBlock),
  encodeUint8(TEST_DWARF.line.standardOpcode.constantAddPc),
  encodeUint8(TEST_DWARF.line.standardOpcode.setPrologueEnd),
  encodeUint8(TEST_DWARF.line.standardOpcode.setEpilogueBegin),
  encodeLineSpecial(TEST_DWARF.line.firstAdvance, TEST_DWARF.line.lineAdvance.unchanged),
  encodeLineExtended(
    TEST_DWARF.line.extendedOpcode.defineFile,
    encodeCString("generated.c"),
    encodeUleb(TEST_DWARF.line.directoryIndex.legacyFirst),
    encodeUleb(TEST_DWARF.line.fileMetadata.unavailable),
    encodeUleb(TEST_DWARF.line.fileMetadata.unavailable)
  ),
  encodeLineExtended(
    TEST_DWARF.line.extendedOpcode.testVendorExtension,
    encodeUint8(TEST_DWARF.encoding.paddingByte)
  ),
  encodeLineExtended(TEST_DWARF.line.extendedOpcode.endSequence)
);

void test("line machine handles the standard, special, and legacy extended opcode families", async () => {
  const dwarf = await analyzeLineSection(
    createDwarf4LineSectionWithProgram(createBroadOpcodeProgram())
  );

  assert.equal(dwarf.linePrograms[0]?.rowCount, TEST_DWARF.line.expected.broadProgramRows);
  assert.equal(
    dwarf.linePrograms[0]?.sequenceCount,
    TEST_DWARF.line.expected.singleSequence
  );
  assert.equal(dwarf.linePrograms[0]?.fileCount, TEST_DWARF.line.expected.broadProgramFiles);
  assert.equal(dwarf.linePrograms[0]?.files.at(-1)?.path, "generated.c");
  const constantAddressAdvance = Math.floor(
    (TEST_DWARF.encoding.maximumByte - TEST_DWARF.line.opcodeBase) /
    TEST_DWARF.line.lineRange
  );
  const expectedAddress = TEST_DWARF.line.address +
    BigInt(constantAddressAdvance + TEST_DWARF.line.firstAdvance);
  assert.equal(dwarf.linePrograms[0]?.minimumAddress, expectedAddress);
  assert.equal(dwarf.linePrograms[0]?.maximumAddress, expectedAddress);
  assert.deepEqual(dwarf.issues, []);
});

void test("line parser supports DWARF 2 and DWARF64 line headers", async () => {
  const versionTwo = await analyzeLineSection(createDwarf2LineSection());
  const dwarf64 = await analyzeLineSection(createDwarf64LineSection());

  assert.equal(versionTwo.linePrograms[0]?.version, TEST_DWARF.version.two);
  assert.equal(versionTwo.linePrograms[0]?.addressSize, TEST_DWARF.addressSize.x64);
  assert.equal(dwarf64.linePrograms[0]?.format, TEST_DWARF.format.dwarf64);
  assert.equal(dwarf64.linePrograms[0]?.rowCount, TEST_DWARF.line.expected.fixtureRows);
});

void test("line parser counts all files while bounding retained file metadata", async () => {
  const declaredFileCount = TEST_DWARF.limits.storedLineFiles + 1;

  const dwarf = await analyzeLineSection(
    createDwarf4LineSectionWithFileCount(declaredFileCount)
  );

  assert.equal(dwarf.linePrograms[0]?.fileCount, declaredFileCount);
  assert.equal(dwarf.linePrograms[0]?.files.length, TEST_DWARF.limits.storedLineFiles);
});

void test("version 5 line tables report unavailable referenced strings", async () => {
  const dwarf = await analyzeLineSection(createDwarf5LineSection());

  assert.equal(dwarf.linePrograms[0]?.fileCount, TEST_DWARF.line.table.singleEntry);
  assert.ok(dwarf.issues.some(issue => issue.includes(".debug_line_str")));
});

void test("line parser reports truncated units without throwing", async () => {
  const complete = createDwarf5LineSection();
  const truncated = complete.slice(0, -Uint8Array.BYTES_PER_ELEMENT);

  const dwarf = await analyzeLineSection(truncated);

  assert.equal(dwarf.linePrograms.length, TEST_DWARF.line.table.singleEntry);
  assert.ok(dwarf.issues.some(issue => issue.includes("extends beyond the section")));
  assert.ok(dwarf.issues.some(issue => issue.includes("Invalid extended line opcode length")));
  assert.ok(dwarf.issues.some(issue => issue.includes("no DW_LNE_end_sequence")));
});

void test("line parser rejects reserved lengths and unsupported versions", async () => {
  const section = Uint8Array.from(createDwarf5LineSection());
  const reserved = withDwarf32InitialLength(section, TEST_DWARF.initialLength.reservedMinimum);
  const unsupportedVersion = new Uint8Array(section);
  unsupportedVersion.set(
    encodeUint16(TEST_DWARF.invalid.version),
    TEST_DWARF.line.offset.version
  );
  const futureVersion = new Uint8Array(section);
  futureVersion.set(
    encodeUint16(TEST_DWARF.invalid.lineVersionHigh),
    TEST_DWARF.line.offset.version
  );
  const zeroLength = withDwarf32InitialLength(section, TEST_DWARF.initialLength.zero);

  const reservedResult = await analyzeLineSection(reserved);
  const versionResult = await analyzeLineSection(unsupportedVersion);
  const futureResult = await analyzeLineSection(futureVersion);
  const zeroResult = await analyzeLineSection(zeroLength);

  assert.ok(reservedResult.issues.some(issue => issue.includes("reserved initial length")));
  assert.ok(versionResult.issues.some(issue => issue.includes("Unsupported DWARF line version")));
  assert.ok(futureResult.issues.some(issue => issue.includes("Unsupported DWARF line version")));
  assert.deepEqual(zeroResult.linePrograms, []);
});

void test("line parser rejects segmented, oversized, and zero-sized header fields", async () => {
  const section = Uint8Array.from(createDwarf5LineSection());
  const segmented = new Uint8Array(section);
  segmented[TEST_DWARF.line.offset.segmentSelectorSize] =
    TEST_DWARF.line.segmentSelectorSize.testUnsupported;
  const oversizedAddress = new Uint8Array(section);
  oversizedAddress[TEST_DWARF.line.offset.addressSize] = TEST_DWARF.invalid.addressSize;
  const zeroAddress = new Uint8Array(section);
  zeroAddress[TEST_DWARF.line.offset.addressSize] = TEST_DWARF.encoding.paddingByte;
  const zeroInstruction = new Uint8Array(section);
  zeroInstruction[TEST_DWARF.line.offset.versionFiveMinimumInstructionLength] =
    TEST_DWARF.encoding.paddingByte;

  const segmentedResult = await analyzeLineSection(segmented);
  const addressResult = await analyzeLineSection(oversizedAddress);
  const zeroAddressResult = await analyzeLineSection(zeroAddress);
  const instructionResult = await analyzeLineSection(zeroInstruction);

  assert.ok(segmentedResult.issues.some(issue => issue.includes("Segmented line addresses")));
  assert.ok(addressResult.issues.some(issue => issue.includes("line address size")));
  assert.ok(zeroAddressResult.issues.some(issue => issue.includes("line address size")));
  assert.ok(instructionResult.issues.some(issue => issue.includes("zero divisor")));
});

void test("line parser rejects a header length outside the declared unit", async () => {
  const section = Uint8Array.from(createDwarf5LineSection());
  section.set(
    encodeUint32(section.length),
    TEST_DWARF.line.offset.versionFiveHeaderLength
  );

  const dwarf = await analyzeLineSection(section);

  assert.deepEqual(dwarf.linePrograms, []);
  assert.ok(dwarf.issues.some(issue => issue.includes("Line header extends beyond")));
});

void test("line parser notices trailing bytes in a known extended opcode", async () => {
  const program = concatenateBytes(
    encodeLineExtended(
      TEST_DWARF.line.extendedOpcode.endSequence,
      encodeUint8(TEST_DWARF.encoding.paddingByte)
    )
  );

  const dwarf = await analyzeLineSection(createDwarf4LineSectionWithProgram(program));

  assert.ok(dwarf.issues.some(issue => issue.includes("trailing extended opcode bytes")));
});
