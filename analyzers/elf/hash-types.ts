export type ElfHashTable = {
  offset: number;
  buckets: number[];
  chains: number[];
  issues: string[];
} & ({ kind: "sysv" } | {
  kind: "gnu";
  symbolOffset: number;
  bloomShift: number;
  bloom: bigint[];
});

export interface ElfHashSource {
  kind: "sysv" | "gnu";
  offset: number;
  size: number;
}
