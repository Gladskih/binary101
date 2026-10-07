"use strict";

import type { FileRangeReader } from "../file-range-reader.js";
import type { DwarfMacroUnit } from "./macro-types.js";
import type { DwarfPublicNames, DwarfAddressLookup } from "./lookup-types.js";
import type { DwarfNameIndex } from "./name-index-types.js";

export type DwarfSectionInput = {
  name: string;
  offset: number;
  size: number;
  compressed: boolean;
  requiresRelocations?: boolean;
};

export type DwarfSectionStatus =
  | "unavailable"
  | "decoded"
  | "referenced"
  | "inventory-only"
  | "compressed-unsupported"
  | "relocations-unsupported";

export type DwarfSectionSummary = DwarfSectionInput & {
  status: DwarfSectionStatus;
};

export type DwarfSectionSource = {
  summary: DwarfSectionInput;
  section: DwarfSectionInput;
  reader: FileRangeReader;
  decoded: boolean;
};

export type DwarfUnitRoot = {
  tag: number;
  name?: string;
  producer?: string;
  language?: number;
  compilationDirectory?: string;
  statementListOffset?: bigint;
};

export type DwarfLineFile = {
  path: string;
  directoryIndex: bigint | null;
  timestamp?: bigint;
  size?: bigint;
  md5?: Uint8Array;
};

export type DwarfLineRow = {
  address: bigint;
  operationIndex: bigint;
  file: bigint;
  line: bigint;
  column: bigint;
  isStatement: boolean;
  basicBlock: boolean;
  endSequence: boolean;
  prologueEnd: boolean;
  epilogueBegin: boolean;
  isa: bigint;
  discriminator: bigint;
};

export type DwarfLineProgram = {
  offset: number;
  length: bigint;
  format: 32 | 64;
  version: number;
  addressSize: number;
  directories: string[];
  files: DwarfLineFile[];
  rows: DwarfLineRow[];
};

export type DwarfTagCount = {
  tag: number;
  count: number;
};

export type DwarfUnit = {
  sectionName: string;
  offset: number;
  length: bigint;
  format: 32 | 64;
  version: number;
  unitType: number | null;
  addressSize: number;
  abbreviationOffset: bigint;
  typeSignature?: bigint;
  typeOffset?: bigint;
  dwoId?: bigint;
  dies: DwarfDie[];
};

export type DwarfAnalysis = {
  sections: DwarfSectionSummary[];
  units: DwarfUnit[];
  linePrograms: DwarfLineProgram[];
  macros?: DwarfMacroUnit[];
  publicNames?: DwarfPublicNames[];
  addressLookup?: DwarfAddressLookup[];
  nameIndexes?: DwarfNameIndex[];
  issues: string[];
};

export type DwarfAbbreviationAttribute = {
  name: number;
  form: number;
  implicitConstant: bigint | null;
};

export type DwarfAbbreviation = {
  tag: number;
  hasChildren: boolean;
  attributes: DwarfAbbreviationAttribute[];
};

export type DwarfUnitContext = {
  version: number;
  format: 32 | 64;
  addressSize: number;
  stringOffsetsBase: bigint | null;
};

export type DwarfFormValue =
  | { kind: "unsigned"; value: bigint }
  | { kind: "signed"; value: bigint }
  | { kind: "string"; value: string }
  | { kind: "string-offset"; value: bigint; sectionName: string }
  | { kind: "string-index"; value: bigint }
  | { kind: "address-index"; value: bigint }
  | { kind: "flag"; value: boolean }
  | { kind: "block"; value: Uint8Array }
  | { kind: "expression"; operations: DwarfExpressionOperation[] }
  | { kind: "ranges"; entries: DwarfAddressRange[] }
  | { kind: "locations"; entries: DwarfLocationEntry[] }
  | { kind: "empty" };

export type DwarfAttribute = {
  name: number;
  form: number;
  value: DwarfFormValue;
};

export type DwarfDie = {
  offset: number;
  tag: number;
  parentOffset: number | null;
  attributes: DwarfAttribute[];
};

export type DwarfExpressionOperation = {
  offset: number;
  opcode: number;
  operands: Array<bigint | Uint8Array | DwarfExpressionOperation[]>;
  incomplete?: true;
};

export type DwarfAddressRange = { start: bigint; end: bigint };
export type DwarfLocationEntry = {
  range: DwarfAddressRange | null;
  operations: DwarfExpressionOperation[];
};
