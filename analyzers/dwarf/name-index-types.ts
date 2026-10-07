import type { DwarfAttribute, DwarfFormValue } from "./types.js";

export type DwarfNameIndexEntry = { offset: number; tag: number; attributes: DwarfAttribute[] };
export type DwarfNameIndex = {
  offset: number;
  format: 32 | 64;
  augmentation: string;
  compileUnits: bigint[];
  localTypeUnits: bigint[];
  foreignTypeUnits: bigint[];
  buckets: number[];
  names: Array<{ name: DwarfFormValue; hash: number | null; entries: DwarfNameIndexEntry[] }>;
};
export type DwarfNameIndexHeader = {
  compileUnitCount: number;
  localTypeUnitCount: number;
  foreignTypeUnitCount: number;
  bucketCount: number;
  nameCount: number;
  abbreviationSize: number;
  augmentation: string;
};
