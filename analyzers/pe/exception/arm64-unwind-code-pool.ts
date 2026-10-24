import { decodeArm64UnwindOperation } from "./arm64-unwind-operations.js";
import type { Arm64DecodedUnwind, Arm64UnwindOperation } from "./arm64-unwind-types.js";

interface UnwindPoolState {
  view: DataView;
  issues: string[];
  cache: Map<number, Arm64UnwindOperation | null>;
  operandOwners: Map<number, number>;
  resolvedPairs: Map<number, Arm64UnwindOperation>;
}

const readOperation = (state: UnwindPoolState, offset: number): Arm64UnwindOperation | null => {
  if (state.operandOwners.has(offset)) {
    state.issues.push(`ARM64 unwind sequence starts inside an operand at byte ${offset}.`);
    return null;
  }
  const cached = state.cache.get(offset);
  if (cached !== undefined) return cached;
  const operation = decodeArm64UnwindOperation(state.view, offset, state.issues);
  state.cache.set(offset, operation);
  if (operation) {
    for (let index = 1; index < operation.byteLength; index++) state.operandOwners.set(offset + index, offset);
  }
  return operation;
};

const NEXT_PAIR_BASES = new Set(["save_r19r20_x", "save_regp", "save_regp_x",
  "save_fregp", "save_fregp_x", "save_any_reg"]);

const registerName = (bank: string, index: number): string => bank === "X" && index === 30 ? "LR" : `${bank}${index}`;

const extendedPair = (base: Arm64UnwindOperation, pairs: number,
  issues: string[]): Arm64UnwindOperation | null => {
  if (base.kind !== "save" || !NEXT_PAIR_BASES.has(base.opcode) || base.registers.length !== 2) return null;
  const bank = base.registers[0]![0]!;
  const first = Number(base.registers[0]!.slice(1)) + pairs * 2;
  if (first + 1 > (bank === "X" ? 30 : 31)) {
    issues.push("ARM64 save_next exceeds its register bank.");
    return null;
  }
  const stride = bank === "Q" ? 32 : 16;
  return { ...base, registers: [registerName(bank, first), registerName(bank, first + 1)], addressing: "offset",
    displacement: (base.addressing === "preIndex" ? 0 : base.displacement) + pairs * stride };
};

const resolveNext = (state: UnwindPoolState, operation: Arm64UnwindOperation): Arm64UnwindOperation => {
  const cached = state.resolvedPairs.get(operation.offset);
  if (cached) return cached;
  let next = operation;
  const prefixes: Arm64UnwindOperation[] = [];
  // Unwind codes reverse prolog order. Microsoft's published unwinder accumulates
  // SAVE_NEXT prefixes, then restores the following pair plus those extensions.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/unwinder/arm64/unwinder.cpp
  while (next.opcode === "save_next") {
    prefixes.push(next);
    const following = readOperation(state, next.offset + next.byteLength);
    if (!following) {
      for (const prefix of prefixes) state.resolvedPairs.set(prefix.offset, prefix);
      return operation;
    }
    next = following;
  }
  for (const [index, prefix] of prefixes.entries()) {
    const resolved = extendedPair(next, prefixes.length - index, state.issues);
    if (!resolved) state.issues.push(`ARM64 save_next at byte ${prefix.offset} has no compatible following pair save.`);
    state.resolvedPairs.set(prefix.offset, resolved ? { ...resolved, opcode: prefix.opcode,
      offset: prefix.offset, byteLength: prefix.byteLength } : prefix);
  }
  return state.resolvedPairs.get(operation.offset)!;
};

const readSequence = (state: UnwindPoolState, start: number,
  operations: Map<number, Arm64UnwindOperation>): void => {
  let offset = start;
  while (offset < state.view.byteLength) {
    if (operations.has(offset)) return;
    const operation = readOperation(state, offset);
    if (!operation) return;
    operations.set(offset,
      operation.opcode === "save_next" ? resolveNext(state, operation) : operation);
    if (operation.opcode === "end") return;
    offset += operation.byteLength;
  }
  state.issues.push(`ARM64 unwind sequence at byte ${start} has no end opcode.`);
};

/** Decode only referenced sequences; shared tails and padding must not inflate inventories. */
export const decodeArm64UnwindPool = (view: DataView, starts: ReadonlySet<number>,
  issues: string[]): Arm64DecodedUnwind => {
  const before = issues.length;
  const state: UnwindPoolState = {
    view, issues, cache: new Map(), operandOwners: new Map(), resolvedPairs: new Map()
  };
  const operations = new Map<number, Arm64UnwindOperation>();
  for (const start of [...starts].sort((left, right) => left - right)) {
    if (!Number.isInteger(start) || start < 0 || start >= view.byteLength) {
      issues.push(`ARM64 unwind sequence index ${start} is outside its code pool.`);
      continue;
    }
    readSequence(state, start, operations);
  }
  return { operations: [...operations.values()].sort((left, right) => left.offset - right.offset),
    hasDecodeGaps: issues.length !== before };
};
