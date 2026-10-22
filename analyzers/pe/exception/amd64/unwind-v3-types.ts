export type Amd64WindingOperation =
  | { opcode: "PUSH" | "PUSH_CONSECUTIVE_2"; register: number }
  | { opcode: "PUSH2"; register: number; register2: number }
  | { opcode: "ALLOC_SMALL" | "ALLOC_LARGE" | "ALLOC_HUGE"; size: number }
  | { opcode: "SET_FPREG" | "SAVE_NONVOL" | "SAVE_NONVOL_FAR" | "SAVE_XMM128" | "SAVE_XMM128_FAR";
    register: number; displacement: number }
  | { opcode: "PUSH_CANONICAL_FRAME"; frameType: number };

export type Amd64UnwindV3Epilog =
  | { kind: "full"; flags: number; offset: number; firstOp: number; lastInstructionOffset: number;
    ipOffsets: number[]; operations: Amd64WindingOperation[] }
  | { kind: "inherited"; flags: number; offset: number; baseEpilogIndex: number | null };

export interface Amd64UnwindV3 {
  flags: number;
  prologSize: number;
  prologIpOffsets: number[];
  prologOperations: Amd64WindingOperation[];
  epilogs: Amd64UnwindV3Epilog[];
}

export interface Amd64UnwindV3Statistics {
  blockCount: number;
  epilogCount: number;
  inheritedEpilogCount: number;
  largePrologCount: number;
  largeEpilogCount: number;
  prologSizeCounts: Record<number, number>;
  operationCounts: Partial<Record<Amd64WindingOperation["opcode"], number>>;
  registerCounts: Record<string, number>;
  allocationCounts: Record<number, number>;
  canonicalFrameTypeCounts: Record<number, number>;
}
