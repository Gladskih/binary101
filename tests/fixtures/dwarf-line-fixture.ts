"use strict";

import {
  TEST_DWARF,
  concatenateBytes,
  encodeCString,
  encodeDwarf32Unit,
  encodeDwarf64Unit,
  encodeSleb,
  encodeUint8,
  encodeUint16,
  encodeUint32,
  encodeUint64,
  encodeUleb
} from "./dwarf-fixture-encoding.js";

const encodeLineBase = (): number[] => encodeUint8(
  BigInt.asUintN(TEST_DWARF.encoding.bitsPerByte, BigInt(TEST_DWARF.line.lineBase))
);

const encodeVersionFourCommonHeader = (): number[] => concatenateBytes(
  encodeUint8(TEST_DWARF.line.minimumInstructionLength),
  encodeUint8(TEST_DWARF.line.maximumOperationsPerInstruction),
  encodeUint8(TEST_DWARF.line.defaultIsStatement),
  encodeLineBase(),
  encodeUint8(TEST_DWARF.line.lineRange),
  encodeUint8(TEST_DWARF.line.opcodeBase),
  TEST_DWARF.line.standardOperandCounts.flatMap(encodeUint8)
);

const encodeVersionTwoCommonHeader = (): number[] => concatenateBytes(
  encodeUint8(TEST_DWARF.line.minimumInstructionLength),
  encodeUint8(TEST_DWARF.line.defaultIsStatement),
  encodeLineBase(),
  encodeUint8(TEST_DWARF.line.lineRange),
  encodeUint8(TEST_DWARF.line.opcodeBase),
  TEST_DWARF.line.standardOperandCounts.flatMap(encodeUint8)
);

export const encodeLineExtended = (opcode: number, ...operands: number[][]): number[] => {
  const payload = concatenateBytes(encodeUint8(opcode), ...operands);
  return concatenateBytes(
    encodeUint8(TEST_DWARF.line.extendedOpcode.marker),
    encodeUleb(payload.length),
    payload
  );
};

const encodeProgram = (): number[] => concatenateBytes(
  encodeLineExtended(
    TEST_DWARF.line.extendedOpcode.setAddress,
    encodeUint64(TEST_DWARF.line.address)
  ),
  encodeUint8(TEST_DWARF.line.standardOpcode.copy),
  encodeUint8(TEST_DWARF.line.standardOpcode.advancePc),
  encodeUleb(TEST_DWARF.line.firstAdvance),
  encodeUint8(TEST_DWARF.line.opcodeBase),
  encodeUint8(TEST_DWARF.line.standardOpcode.fixedAdvancePc),
  encodeUint16(TEST_DWARF.line.fixedAdvance),
  encodeLineExtended(
    TEST_DWARF.line.extendedOpcode.setDiscriminator,
    encodeUleb(TEST_DWARF.line.discriminator)
  ),
  encodeUint8(TEST_DWARF.line.standardOpcode.setIsa),
  encodeUleb(TEST_DWARF.line.isa),
  encodeLineExtended(TEST_DWARF.line.extendedOpcode.endSequence)
);

export const createDwarf4LineSectionWithProgram = (program: number[]): number[] => {
  const tables = concatenateBytes(
    encodeCString("src"),
    encodeCString(""),
    encodeCString("main.c"),
    encodeUleb(TEST_DWARF.line.directoryIndex.legacyFirst),
    encodeUleb(TEST_DWARF.line.fileMetadata.unavailable),
    encodeUleb(TEST_DWARF.line.fileMetadata.unavailable),
    encodeCString("")
  );
  const header = concatenateBytes(encodeVersionFourCommonHeader(), tables);
  return encodeDwarf32Unit(concatenateBytes(
    encodeUint16(TEST_DWARF.version.four),
    encodeUint32(header.length),
    header,
    program
  ));
};

export const createDwarf4LineSectionWithFileCount = (fileCount: number): number[] => {
  const fileEntries = Array.from({ length: fileCount }, () => concatenateBytes(
    encodeCString("repeated.c"),
    encodeUleb(TEST_DWARF.line.directoryIndex.legacyFirst),
    encodeUleb(TEST_DWARF.line.fileMetadata.unavailable),
    encodeUleb(TEST_DWARF.line.fileMetadata.unavailable)
  ));
  const tables = concatenateBytes(
    encodeCString(""),
    ...fileEntries,
    encodeCString("")
  );
  const header = concatenateBytes(encodeVersionFourCommonHeader(), tables);
  return encodeDwarf32Unit(concatenateBytes(
    encodeUint16(TEST_DWARF.version.four),
    encodeUint32(header.length),
    header
  ));
};

export const createDwarf4LineSection = (): number[] =>
  createDwarf4LineSectionWithProgram(encodeProgram());

export const createDwarf2LineSection = (): number[] => {
  const tables = concatenateBytes(encodeCString(""), encodeCString(""));
  const header = concatenateBytes(encodeVersionTwoCommonHeader(), tables);
  return encodeDwarf32Unit(concatenateBytes(
    encodeUint16(TEST_DWARF.version.two),
    encodeUint32(header.length),
    header,
    encodeProgram()
  ));
};

export const createDwarf64LineSection = (): number[] => {
  const tables = concatenateBytes(encodeCString(""), encodeCString(""));
  const header = concatenateBytes(encodeVersionFourCommonHeader(), tables);
  return encodeDwarf64Unit(concatenateBytes(
    encodeUint16(TEST_DWARF.version.four),
    encodeUint64(header.length),
    header,
    encodeProgram()
  ));
};

export const createDwarf5LineStrings = (): number[] => concatenateBytes(
  encodeCString("src"),
  encodeCString("lib.rs")
);

export const createDwarf5LineSection = (): number[] => {
  const directoryFormats = concatenateBytes(
    encodeUint8(TEST_DWARF.line.table.singleEntry),
    encodeUleb(TEST_DWARF.line.content.path),
    encodeUleb(TEST_DWARF.form.lineStringPointer)
  );
  const directories = concatenateBytes(
    encodeUleb(TEST_DWARF.line.table.singleEntry),
    encodeUint32(TEST_DWARF.sectionOffset.start)
  );
  const fileFormats = concatenateBytes(
    encodeUint8(TEST_DWARF.line.content.directoryIndex),
    encodeUleb(TEST_DWARF.line.content.path),
    encodeUleb(TEST_DWARF.form.lineStringPointer),
    encodeUleb(TEST_DWARF.line.content.directoryIndex),
    encodeUleb(TEST_DWARF.form.unsignedData)
  );
  const files = concatenateBytes(
    encodeUleb(TEST_DWARF.line.table.singleEntry),
    encodeUint32(encodeCString("src").length),
    encodeUleb(TEST_DWARF.line.directoryIndex.versionFiveFirst)
  );
  const header = concatenateBytes(
    encodeVersionFourCommonHeader(), directoryFormats, directories, fileFormats, files
  );
  return encodeDwarf32Unit(concatenateBytes(
    encodeUint16(TEST_DWARF.version.five),
    encodeUint8(TEST_DWARF.addressSize.x64),
    encodeUint8(TEST_DWARF.line.segmentSelectorSize.none),
    encodeUint32(header.length),
    header,
    encodeProgram()
  ));
};

export const encodeLineSpecial = (addressAdvance: number, lineAdvance: number): number[] =>
  encodeUint8(
    TEST_DWARF.line.opcodeBase +
    addressAdvance * TEST_DWARF.line.lineRange +
    lineAdvance - TEST_DWARF.line.lineBase
  );

export const encodeLineAdvance = (lineAdvance: number): number[] => concatenateBytes(
  encodeUint8(TEST_DWARF.line.standardOpcode.advanceLine),
  encodeSleb(lineAdvance)
);
