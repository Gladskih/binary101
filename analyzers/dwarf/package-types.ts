export type DwarfPackageContribution = { offset: number; size: number };
export type DwarfPackageIndex = {
  sectionName: string;
  version: 2 | 5;
  slots: Array<{ signature: bigint; row: number }>;
  columns: number[];
  rows: DwarfPackageContribution[][];
};
export type DwarfPackageHeader = {
  version: 2 | 5;
  sectionCount: number;
  unitCount: number;
  slotCount: number;
};
