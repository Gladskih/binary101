"use strict";

import { dwarfTagLabel } from "./tag-names.js";

// DWARF 5 encoding tables, sections 7.3 through 7.5:
// https://dwarfstd.org/doc/DWARF5.pdf
export const DWARF_TAG = {
  arrayType: 0x01,
  classType: 0x02,
  enumerationType: 0x04,
  formalParameter: 0x05,
  enumerator: 0x28,
  inlinedSubroutine: 0x1d,
  namespace: 0x39,
  constType: 0x26,
  volatileType: 0x35,
  restrictType: 0x37,
  referenceType: 0x10,
  rvalueReferenceType: 0x42,
  member: 0x0d,
  pointerType: 0x0f,
  compileUnit: 0x11,
  structureType: 0x13,
  subroutineType: 0x15,
  typedef: 0x16,
  unionType: 0x17,
  subrangeType: 0x21,
  baseType: 0x24,
  subprogram: 0x2e,
  variable: 0x34,
  unspecifiedType: 0x3b,
  typeUnit: 0x41,
  skeletonUnit: 0x4a,
  immutableType: 0x4b
} as const;

export const DWARF_UNIT_TYPE = {
  compile: 0x01,
  type: 0x02,
  partial: 0x03,
  skeleton: 0x04,
  splitCompile: 0x05,
  splitType: 0x06
} as const;

export const DWARF_ATTRIBUTE = {
  location: 0x02,
  name: 0x03,
  byteSize: 0x0b,
  bitSize: 0x0d,
  statementList: 0x10,
  lowPc: 0x11,
  highPc: 0x12,
  language: 0x13,
  constantValue: 0x1c,
  compilationDirectory: 0x1b,
  lowerBound: 0x22,
  producer: 0x25,
  upperBound: 0x2f,
  abstractOrigin: 0x31,
  accessibility: 0x32,
  artificial: 0x34,
  count: 0x37,
  dataMemberLocation: 0x38,
  declarationColumn: 0x39,
  declarationFile: 0x3a,
  declarationLine: 0x3b,
  declaration: 0x3c,
  encoding: 0x3e,
  external: 0x3f,
  frameBase: 0x40,
  specification: 0x47,
  type: 0x49,
  ranges: 0x55,
  callColumn: 0x57,
  callFile: 0x58,
  callLine: 0x59,
  dataBitOffset: 0x6b,
  linkageName: 0x6e,
  stringOffsetsBase: 0x72,
  addressBase: 0x73,
  rangeListsBase: 0x74,
  dwoName: 0x76,
  macros: 0x79,
  locationListsBase: 0x8c
} as const;

export const DWARF_FORM = {
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
  referenceAddress: 0x10,
  reference1: 0x11,
  reference2: 0x12,
  reference4: 0x13,
  reference8: 0x14,
  referenceUnsigned: 0x15,
  indirect: 0x16,
  sectionOffset: 0x17,
  expressionLocation: 0x18,
  flagPresent: 0x19,
  stringIndex: 0x1a,
  addressIndex: 0x1b,
  referenceSupplementary4: 0x1c,
  stringPointerSupplementary: 0x1d,
  data16: 0x1e,
  lineStringPointer: 0x1f,
  referenceSignature8: 0x20,
  implicitConstant: 0x21,
  locationListIndex: 0x22,
  rangeListIndex: 0x23,
  referenceSupplementary8: 0x24,
  stringIndex1: 0x25,
  stringIndex2: 0x26,
  stringIndex3: 0x27,
  stringIndex4: 0x28,
  addressIndex1: 0x29,
  addressIndex2: 0x2a,
  addressIndex3: 0x2b,
  addressIndex4: 0x2c,
  gnuAddressIndex: 0x1f01,
  gnuStringIndex: 0x1f02,
  gnuReferenceAlternate: 0x1f20,
  gnuStringPointerAlternate: 0x1f21
} as const;

export const DWARF_CHILDREN = {
  no: 0,
  yes: 1
} as const;

export const DWARF_SENTINEL = {
  abbreviationTableEnd: 0n,
  attributeListEnd: 0n,
  nullDie: 0n,
  zeroUnitLength: 0n
} as const;

export const DWARF_INITIAL_LENGTH = {
  reservedMinimum: 0xfffffff0,
  format64Escape: 0xffffffff
} as const;

export const DWARF_VERSION = {
  minimumSupported: 2,
  maximumSupported: 5,
  maximumOperationsPerInstructionIntroduced: 4,
  referenceAddressUsesAddressSizeThrough: 2
} as const;

export const DWARF_FORMAT = {
  dwarf32: 32,
  dwarf64: 64
} as const;

export const DWARF_ENCODING = {
  bitsPerByte: 8,
  data16Bytes: 16,
  lebContinuationBit: 0x80,
  lebPayloadBits: 7,
  lebPayloadMask: 0x7f,
  lebSignBit: 0x40,
  nullByte: 0
} as const;

export const DWARF_SECTION = {
  abbreviations: ".debug_abbrev",
  information: ".debug_info",
  lines: ".debug_line",
  lineStrings: ".debug_line_str",
  stringOffsets: ".debug_str_offsets",
  strings: ".debug_str",
  types: ".debug_types"
} as const;

// DWARF 5 line number program encodings, sections 6.2 and 7.22:
// https://dwarfstd.org/doc/DWARF5.pdf
export const DWARF_LINE_STANDARD_OPCODE = {
  copy: 0x01,
  advancePc: 0x02,
  advanceLine: 0x03,
  setFile: 0x04,
  setColumn: 0x05,
  negateStatement: 0x06,
  setBasicBlock: 0x07,
  constantAddPc: 0x08,
  fixedAdvancePc: 0x09,
  setPrologueEnd: 0x0a,
  setEpilogueBegin: 0x0b,
  setIsa: 0x0c
} as const;

export const DWARF_LINE_ENCODING = {
  extendedOpcodeMarker: 0,
  firstStandardOpcode: 1,
  maximumOpcode: 0xff,
  noSegmentSelectorBytes: 0,
  unknownLegacyAddressSize: 0,
  initialAddress: 0n,
  initialOperationIndex: 0n
} as const;

export const DWARF_LINE_EXTENDED_OPCODE = {
  endSequence: 0x01,
  setAddress: 0x02,
  defineFile: 0x03,
  setDiscriminator: 0x04
} as const;

export const DWARF_LINE_CONTENT = {
  path: 0x01,
  directoryIndex: 0x02,
  timestamp: 0x03,
  size: 0x04,
  md5: 0x05
} as const;

export const DWARF_LANGUAGE = {
  c89: 0x0001,
  c: 0x0002,
  cpp: 0x0004,
  pascal83: 0x0009,
  c99: 0x000c,
  python: 0x0014,
  go: 0x0016,
  cpp03: 0x0019,
  cpp11: 0x001a,
  rust: 0x001c,
  c11: 0x001d,
  swift: 0x001e,
  cpp14: 0x0021,
  kotlin: 0x0026,
  zig: 0x0027,
  cpp17: 0x002a,
  cpp20: 0x002b,
  c17: 0x002c,
  assembly: 0x0031,
  cSharp: 0x0032,
  cpp23: 0x003a,
  c23: 0x003e
} as const;

const UNIT_TYPE_NAMES = new Map<number, string>([
  [DWARF_UNIT_TYPE.compile, "DW_UT_compile"],
  [DWARF_UNIT_TYPE.type, "DW_UT_type"],
  [DWARF_UNIT_TYPE.partial, "DW_UT_partial"],
  [DWARF_UNIT_TYPE.skeleton, "DW_UT_skeleton"],
  [DWARF_UNIT_TYPE.splitCompile, "DW_UT_split_compile"],
  [DWARF_UNIT_TYPE.splitType, "DW_UT_split_type"]
]);

// DWARF Committee assigned language codes: https://dwarfstd.org/languages.html
const LANGUAGE_NAMES = new Map<number, string>([
  [DWARF_LANGUAGE.c89, "DW_LANG_C89"], [DWARF_LANGUAGE.c, "DW_LANG_C"],
  [DWARF_LANGUAGE.cpp, "DW_LANG_C_plus_plus"],
  [DWARF_LANGUAGE.pascal83, "DW_LANG_Pascal83"],
  [DWARF_LANGUAGE.c99, "DW_LANG_C99"], [DWARF_LANGUAGE.python, "DW_LANG_Python"],
  [DWARF_LANGUAGE.go, "DW_LANG_Go"], [DWARF_LANGUAGE.cpp03, "DW_LANG_C_plus_plus_03"],
  [DWARF_LANGUAGE.cpp11, "DW_LANG_C_plus_plus_11"], [DWARF_LANGUAGE.rust, "DW_LANG_Rust"],
  [DWARF_LANGUAGE.c11, "DW_LANG_C11"], [DWARF_LANGUAGE.swift, "DW_LANG_Swift"],
  [DWARF_LANGUAGE.cpp14, "DW_LANG_C_plus_plus_14"],
  [DWARF_LANGUAGE.kotlin, "DW_LANG_Kotlin"],
  [DWARF_LANGUAGE.zig, "DW_LANG_Zig"], [DWARF_LANGUAGE.cpp17, "DW_LANG_C_plus_plus_17"],
  [DWARF_LANGUAGE.cpp20, "DW_LANG_C_plus_plus_20"], [DWARF_LANGUAGE.c17, "DW_LANG_C17"],
  [DWARF_LANGUAGE.assembly, "DW_LANG_Assembly"],
  [DWARF_LANGUAGE.cSharp, "DW_LANG_C_sharp"],
  [DWARF_LANGUAGE.cpp23, "DW_LANG_C_plus_plus_23"], [DWARF_LANGUAGE.c23, "DW_LANG_C23"]
]);

const hexName = (prefix: string, value: number): string =>
  `${prefix}_0x${value.toString(16)}`;

export const dwarfTagName = (tag: number): string =>
  dwarfTagLabel(tag).startsWith("DW_TAG_") ? dwarfTagLabel(tag) : `DW_TAG_${dwarfTagLabel(tag)}`;

export const dwarfUnitTypeName = (unitType: number): string =>
  UNIT_TYPE_NAMES.get(unitType) ?? hexName("DW_UT", unitType);

export const dwarfLanguageName = (language: number): string =>
  LANGUAGE_NAMES.get(language) ?? hexName("DW_LANG", language);
