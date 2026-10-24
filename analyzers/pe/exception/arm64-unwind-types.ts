export interface Arm64UnwindSave {
  kind: "save";
  registers: string[];
  displacement: number;
  addressing: "offset" | "preIndex";
  unit: "bytes" | "vectorLengths" | "predicateLengths";
}

export type Arm64UnwindBody = Arm64UnwindSave
  | { kind: "allocate"; amount: number; unit: "bytes" | "vectorLengths" }
  | { kind: "frame"; displacement: number }
  | { kind: "marker" };

export type Arm64UnwindOperation = Arm64UnwindBody & {
  opcode: string;
  offset: number;
  byteLength: number;
};

export interface Arm64DecodedUnwind {
  operations: Arm64UnwindOperation[];
  hasDecodeGaps: boolean;
}

export interface Arm64XdataCodeLayout {
  codeRva: number;
  codeSize: number;
  scopeRva: number;
  scopeCount: number;
  epilogIndex: number | null;
}

export interface Arm64UnwindStatistics {
  blockCount: number;
  incompleteBlockCount: number;
  operationCounts: Record<string, number>;
  registerCounts: Record<string, number>;
  allocationCounts: Record<number, number>;
  preIndexAdjustmentCounts: Record<number, number>;
  scalableAllocationCounts: Record<number, number>;
  saveOffsetCounts: Record<number, number>;
  scalableSaveCounts: Record<string, number>;
  frameOffsetCounts: Record<number, number>;
}
