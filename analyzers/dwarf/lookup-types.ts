export type DwarfPublicName = { dieOffset: bigint; name: string; descriptor: number | null };
export type DwarfPublicNames = {
  sectionName: string;
  offset: number;
  format: 32 | 64;
  unitOffset: bigint;
  unitLength: bigint;
  entries: DwarfPublicName[];
};
export type DwarfAddressLookup = {
  offset: number;
  format: 32 | 64;
  unitOffset: bigint;
  addressSize: number;
  segmentSize: number;
  ranges: Array<{ segment: bigint | null; start: bigint; length: bigint }>;
};
