"use strict";

// Independent test oracle from DWARF 5 Tables 7.3, 7.5, 7.17, 7.19, and 7.21:
// https://dwarfstd.org/doc/DWARF5.pdf
export const TEST_DWARF = {
  encoding: {
    bitsPerByte: 8,
    bitsPerLebByte: 7,
    asciiNul: 0,
    paddingByte: 0,
    maximumByte: 0xff,
    byteMask: 0xffn,
    lebContinuation: 0x80,
    lebPayloadMask: 0x7fn,
    lebSignBit: 0x40,
    lebTerminator: 0
  },
  version: { two: 2, four: 4, five: 5 },
  format: { dwarf32: 32, dwarf64: 64 },
  children: { no: 0, yes: 1 },
  flag: { present: 1 },
  abbreviationCode: { null: 0, compileUnit: 1, subprogram: 2 },
  abbreviationTerminator: { attributeName: 0, attributeForm: 0, table: 0 },
  unitType: { compile: 0x01, type: 0x02 },
  tag: { compileUnit: 0x11, subprogram: 0x2e },
  attribute: { name: 0x03, statementList: 0x10, language: 0x13, producer: 0x25 },
  form: {
    address: 0x01,
    block2: 0x03,
    block4: 0x04,
    data2: 0x05,
    data4: 0x06,
    data8: 0x07,
    string: 0x08,
    block: 0x09,
    block1: 0x0a,
    data1: 0x0b,
    flag: 0x0c,
    signedData: 0x0d,
    stringPointer: 0x0e,
    unsignedData: 0x0f,
    reference1: 0x11,
    indirect: 0x16,
    sectionOffset: 0x17,
    expressionLocation: 0x18,
    flagPresent: 0x19,
    stringIndex: 0x1a,
    data16: 0x1e,
    lineStringPointer: 0x1f,
    implicitConstant: 0x21,
    stringIndex1: 0x25,
    stringIndex4: 0x28,
    addressIndex1: 0x29,
    addressIndex4: 0x2c,
    gnuAddressIndex: 0x1f01,
    gnuStringIndex: 0x1f02
  },
  language: { c99: 0x0c, rust: 0x1c },
  stringIndex: { foo: 1 },
  initialLength: {
    offset: 0,
    zero: 0,
    format64Escape: 0xffffffff,
    reservedMinimum: 0xfffffff0
  },
  sectionOffset: { start: 0 },
  encodedSize: { data16: 16 },
  addressSize: { x64: 8 },
  line: {
    minimumInstructionLength: 1,
    maximumOperationsPerInstruction: 1,
    defaultIsStatement: 1,
    lineBase: -5,
    lineRange: 14,
    opcodeBase: 13,
    standardOperandCounts: [0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1],
    standardOpcode: {
      copy: 1, advancePc: 2, advanceLine: 3,
      setFile: 4, setColumn: 5, negateStatement: 6,
      setBasicBlock: 7, constantAddPc: 8, fixedAdvancePc: 9,
      setPrologueEnd: 10, setEpilogueBegin: 11,
      setIsa: 12
    },
    extendedOpcode: {
      marker: 0,
      endSequence: 1,
      setAddress: 2,
      defineFile: 3,
      setDiscriminator: 4,
      testVendorExtension: 0x7f
    },
    content: { path: 1, directoryIndex: 2 },
    table: { singleEntry: 1 },
    directoryIndex: { legacyFirst: 1, versionFiveFirst: 0 },
    offset: {
      version: 4,
      addressSize: 6,
      segmentSelectorSize: 7,
      versionFiveHeaderLength: 8,
      versionFiveMinimumInstructionLength: 12
    },
    segmentSelectorSize: { none: 0, testUnsupported: 1 },
    fileMetadata: { unavailable: 0 },
    lineAdvance: { previous: -1, unchanged: 0 },
    address: 0x1000n,
    firstAdvance: 4,
    fixedAdvance: 2,
    discriminator: 7,
    isa: 1,
    expected: {
      fixtureRows: 3,
      broadProgramRows: 2,
      broadProgramFiles: 2,
      singleSequence: 1
    }
  },
  invalid: {
    abbreviationCode: 99,
    addressSize: 16,
    children: 2,
    form: 0xffff,
    unitType: 7,
    version: 1,
    lineVersionHigh: 6
  },
  limits: { displayedStringBytes: 4096, maximumLebBytes: 10, storedLineFiles: 1024 }
} as const;

export const TEST_INTEGER = {
  uint8: 0x12,
  uint16: 0x1234,
  uint32: 0x12345678,
  ascendingUint64: 0x0807060504030201n,
  multibyteUleb: 129n,
  negativeSleb: -1n,
  implicitConstant: -3n
} as const;

export type TestAbbreviation = {
  code: bigint | number;
  tag: bigint | number;
  children: number;
  attributes: Array<{
    name: bigint | number;
    form: bigint | number;
    implicitConstant?: bigint | number;
  }>;
};

export const concatenateBytes = (...parts: number[][]): number[] => parts.flat();

export const encodeRepeatedByte = (value: number, count: number): number[] =>
  Array.from({ length: count }, () => value);

export const encodeUnterminatedLeb = (byteCount: number): number[] =>
  encodeRepeatedByte(TEST_DWARF.encoding.lebContinuation, byteCount);

export const encodeLebTerminatedAfter = (continuationCount: number): number[] =>
  concatenateBytes(
    encodeUnterminatedLeb(continuationCount),
    encodeUint8(TEST_DWARF.encoding.lebTerminator)
  );

export const encodeSequence = (count: number, first = 1): number[] =>
  Array.from({ length: count }, (_, index) => first + index);

export const encodeUnsigned = (
  value: bigint | number,
  byteCount: number
): number[] => {
  const result = new Array<number>(byteCount);
  let remaining = BigInt(value);
  for (let index = 0; index < byteCount; index += 1) {
    result[index] = Number(remaining & TEST_DWARF.encoding.byteMask);
    remaining >>= BigInt(TEST_DWARF.encoding.bitsPerByte);
  }
  return result;
};

export const encodeBigEndianUnsigned = (
  value: bigint | number,
  byteCount: number
): number[] => encodeUnsigned(value, byteCount).reverse();

export const encodeUint8 = (value: bigint | number): number[] => encodeUnsigned(value, 1);
export const encodeUint16 = (value: bigint | number): number[] => encodeUnsigned(value, 2);
export const encodeUint32 = (value: bigint | number): number[] => encodeUnsigned(value, 4);
export const encodeUint64 = (value: bigint | number): number[] => encodeUnsigned(value, 8);

export const encodeDwarf5HeaderBody = (
  unitType: number,
  addressSize: number,
  abbreviationOffset: bigint | number,
  format: 32 | 64,
  ...typedFields: number[][]
): number[] => concatenateBytes(
  encodeUint16(TEST_DWARF.version.five),
  encodeUint8(unitType),
  encodeUint8(addressSize),
  encodeUnsigned(abbreviationOffset, format / TEST_DWARF.encoding.bitsPerByte),
  ...typedFields
);

export const encodeLegacyHeaderBody = (
  version: number,
  addressSize: number,
  abbreviationOffset: bigint | number,
  ...typedFields: number[][]
): number[] => concatenateBytes(
  encodeUint16(version),
  encodeUint32(abbreviationOffset),
  encodeUint8(addressSize),
  ...typedFields
);

export const encodeBlock1 = (payload: number[]): number[] =>
  concatenateBytes(encodeUint8(payload.length), payload);

export const encodeBlock2 = (payload: number[]): number[] =>
  concatenateBytes(encodeUint16(payload.length), payload);

export const encodeBlock4 = (payload: number[]): number[] =>
  concatenateBytes(encodeUint32(payload.length), payload);

export const encodeUleb = (value: bigint | number): number[] => {
  const result: number[] = [];
  let remaining = BigInt(value);
  do {
    const byte = Number(remaining & TEST_DWARF.encoding.lebPayloadMask);
    remaining >>= BigInt(TEST_DWARF.encoding.bitsPerLebByte);
    result.push(remaining === 0n ? byte : byte | TEST_DWARF.encoding.lebContinuation);
  } while (remaining !== 0n);
  return result;
};

export const encodeVariableBlock = (payload: number[]): number[] =>
  concatenateBytes(encodeUleb(payload.length), payload);

export const encodeSleb = (value: bigint | number): number[] => {
  const result: number[] = [];
  let remaining = BigInt(value);
  let complete = false;
  while (!complete) {
    const byte = Number(remaining & TEST_DWARF.encoding.lebPayloadMask);
    remaining >>= BigInt(TEST_DWARF.encoding.bitsPerLebByte);
    const signBitSet = (byte & TEST_DWARF.encoding.lebSignBit) !== 0;
    complete = (remaining === 0n && !signBitSet) || (remaining === -1n && signBitSet);
    result.push(complete ? byte : byte | TEST_DWARF.encoding.lebContinuation);
  }
  return result;
};

export const encodeCString = (value: string): number[] => [
  ...new TextEncoder().encode(value),
  TEST_DWARF.encoding.asciiNul
];

export const encodeText = (value: string): number[] => [
  ...new TextEncoder().encode(value)
];

export const encodeDie = (abbreviationCode: bigint | number, ...values: number[][]): number[] =>
  concatenateBytes(encodeUleb(abbreviationCode), ...values);

export const encodeNullDie = (): number[] => encodeUleb(TEST_DWARF.abbreviationCode.null);

export const encodeAbbreviationTable = (entries: TestAbbreviation[]): number[] => {
  const encoded = entries.flatMap(entry => concatenateBytes(
    encodeUleb(entry.code),
    encodeUleb(entry.tag),
    encodeUint8(entry.children),
    entry.attributes.flatMap(attribute => concatenateBytes(
      encodeUleb(attribute.name),
      encodeUleb(attribute.form),
      attribute.implicitConstant == null ? [] : encodeSleb(attribute.implicitConstant)
    )),
    encodeUleb(TEST_DWARF.abbreviationTerminator.attributeName),
    encodeUleb(TEST_DWARF.abbreviationTerminator.attributeForm)
  ));
  return concatenateBytes(encoded, encodeUleb(TEST_DWARF.abbreviationTerminator.table));
};

export const encodeDwarf32Unit = (body: number[], declaredLength = body.length): number[] =>
  concatenateBytes(encodeUint32(declaredLength), body);

export const encodeDwarf64Unit = (body: number[], declaredLength = body.length): number[] =>
  concatenateBytes(
    encodeUint32(TEST_DWARF.initialLength.format64Escape),
    encodeUint64(declaredLength),
    body
  );

export const withDwarf32InitialLength = (
  source: Uint8Array,
  initialLength: number
): Uint8Array => {
  const result = new Uint8Array(source);
  result.set(encodeUint32(initialLength), TEST_DWARF.initialLength.offset);
  return result;
};
