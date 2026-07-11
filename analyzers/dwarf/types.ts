"use strict";

import type { FileRangeReader } from "../file-range-reader.js";

export type DwarfSectionInput = {
  name: string;
  offset: number;
  size: number;
  compressed: boolean;
  requiresRelocations?: boolean;
};

export type DwarfSectionStatus =
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
};

export type DwarfLineProgram = {
  offset: number;
  length: bigint;
  format: 32 | 64;
  version: number;
  addressSize: number;
  directoryCount: number;
  fileCount: number;
  files: DwarfLineFile[];
  rowCount: number;
  sequenceCount: number;
  minimumAddress: bigint | null;
  maximumAddress: bigint | null;
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
  root: DwarfUnitRoot | null;
  tagCounts: DwarfTagCount[];
  maxDepth: number;
};

export type DwarfAnalysis = {
  sections: DwarfSectionSummary[];
  units: DwarfUnit[];
  linePrograms: DwarfLineProgram[];
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
  | { kind: "flag"; value: boolean }
  | { kind: "empty" };
