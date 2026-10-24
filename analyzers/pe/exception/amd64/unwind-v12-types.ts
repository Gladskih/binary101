export type Amd64UnwindOperationBody =
  | { opcode: "PUSH_NONVOL"; register: number }
  | { opcode: "ALLOC_SMALL" | "ALLOC_LARGE"; size: number }
  | { opcode: "SET_FPREG" }
  | { opcode: "SAVE_NONVOL" | "SAVE_NONVOL_FAR" | "SAVE_XMM128" | "SAVE_XMM128_FAR";
    register: number; displacement: number }
  | { opcode: "PUSH_MACHFRAME"; size: number };

export type Amd64UnwindOperation = Amd64UnwindOperationBody & { codeOffset: number };

export interface Amd64UnwindV12Header {
  prologSize: number;
  frameRegister: number;
  frameOffset: number;
}

export interface Amd64UnwindV12Statistics {
  blockCount: number;
  incompleteBlockCount: number;
  operationCounts: Record<string, number>;
  registerCounts: Record<string, number>;
  allocationCounts: Record<number, number>;
  saveOffsetCounts: Record<number, number>;
  frameRegisterCounts: Record<string, number>;
  frameOffsetCounts: Record<number, number>;
  machineFrameCounts: Record<number, number>;
  prologSizeCounts: Record<number, number>;
}
