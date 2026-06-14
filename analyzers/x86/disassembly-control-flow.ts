"use strict";

import type { IcedX86Module } from "./disassembly-iced.js";
import { getNearBranchTarget } from "./disassembly-branch-targets.js";

type DisassemblySection = {
  rvaStart: number;
  data: Uint8Array<ArrayBufferLike>;
};

type DisassemblyYieldSnapshot = {
  bytesDecoded: number;
  instructionCount: number;
  invalidInstructionCount: number;
};

type DisassemblyDecoderEntry = DisassemblySection & {
  decoder: InstanceType<IcedX86Module["Decoder"]>;
};

type ControlFlowDecodeState = {
  iced: IcedX86Module;
  imageBase: bigint;
  bytesSampled: number;
  decoders: DisassemblyDecoderEntry[];
  visited: Set<number>;
  queued: Set<number>;
  queue: number[];
  featureCounts: Map<number, number>;
  yieldEveryInstructions: number;
  signal?: AbortSignal;
  onYield?: (snapshot: DisassemblyYieldSnapshot) => Promise<void>;
  bytesDecoded: number;
  instructionCount: number;
  invalidInstructionCount: number;
  recordDecodeStopIssue(message: string): void;
};

const MAX_RVA = 0xffff_ffff;
const MAX_DECODE_STOP_ISSUES = 200;

const toRva = (ip: bigint, imageBase: bigint): number | null => {
  if (ip < imageBase) return null;
  const delta = ip - imageBase;
  if (delta > BigInt(MAX_RVA)) return null;
  const value = Number(delta);
  if (!Number.isSafeInteger(value) || value < 0) return null;
  return value >>> 0;
};

const safeFree = (resource: { free(): void } | null | undefined): void => {
  if (!resource) return;
  try {
    resource.free();
  } catch {
    // Best-effort cleanup: iced-x86 objects own WASM allocations and `free()` may throw if the module
    // is partially initialized/aborted or if the object has already been released.
    // Cleanup errors should never override real analysis results.
  }
};

const snapshot = (state: ControlFlowDecodeState): DisassemblyYieldSnapshot => ({
  bytesDecoded: state.bytesDecoded,
  instructionCount: state.instructionCount,
  invalidInstructionCount: state.invalidInstructionCount
});

const getDecoderForRva = (
  decoders: DisassemblyDecoderEntry[],
  rva: number
): DisassemblyDecoderEntry | null => {
  for (const entry of decoders) {
    const start = entry.rvaStart;
    const end = start + entry.data.length;
    if (rva >= start && rva < end) return entry;
  }
  return null;
};

const addControlFlowWork = (state: ControlFlowDecodeState, rva: number | null): void => {
  if (rva == null) return;
  const normalized = rva >>> 0;
  if (state.visited.has(normalized) || state.queued.has(normalized)) return;
  state.queue.push(normalized);
  state.queued.add(normalized);
};

const countInstructionFeatures = (state: ControlFlowDecodeState, instr: InstanceType<IcedX86Module["Instruction"]>): void => {
  const features = instr.cpuidFeatures();
  for (const feature of features) {
    state.featureCounts.set(feature, (state.featureCounts.get(feature) || 0) + 1);
  }
};

const decodeLinearRun = async (
  state: ControlFlowDecodeState,
  decoderEntry: DisassemblyDecoderEntry,
  startRva: number,
  instr: InstanceType<IcedX86Module["Instruction"]>
): Promise<void> => {
  const offset = startRva - decoderEntry.rvaStart;
  if (offset < 0 || offset >= decoderEntry.data.length) return;
  const decoder = decoderEntry.decoder;
  decoder.position = offset;
  decoder.ip = BigInt.asUintN(64, state.imageBase + BigInt(startRva));
  while (decoder.canDecode) {
    if (state.signal?.aborted) return;
    decoder.decodeOut(instr);
    state.instructionCount += 1;
    const instrRva = toRva(instr.ip, state.imageBase);
    if (instrRva == null) break;
    if (state.visited.has(instrRva)) break;
    state.visited.add(instrRva);
    const len = instr.length;
    if (len <= 0) {
      state.invalidInstructionCount += 1;
      state.recordDecodeStopIssue("Stopping at a zero-length instruction decode.");
      break;
    }
    state.bytesDecoded = Math.min(state.bytesSampled, state.bytesDecoded + len);
    const isInvalidDecode = instr.code === state.iced.Code["INVALID"];
    const isUd2Trap = instr.code === state.iced.Code["Ud2"];
    const isHardException = instr.flowControl === state.iced.FlowControl["Exception"] && !isUd2Trap;
    if (isInvalidDecode || isHardException) {
      state.invalidInstructionCount += 1;
      state.recordDecodeStopIssue(`Stopping at an invalid instruction at RVA 0x${instrRva.toString(16)}.`);
      break;
    }
    if (!isUd2Trap) countInstructionFeatures(state, instr);
    if (state.iced.FlowControl["UnconditionalBranch"] === instr.flowControl) {
      const target = getNearBranchTarget(instr, state.iced.OpKind);
      addControlFlowWork(state, target == null ? null : toRva(target, state.imageBase));
      break;
    }
    if (
      state.iced.FlowControl["ConditionalBranch"] === instr.flowControl ||
      state.iced.FlowControl["Call"] === instr.flowControl ||
      state.iced.FlowControl["XbeginXabortXend"] === instr.flowControl
    ) {
      const target = getNearBranchTarget(instr, state.iced.OpKind);
      addControlFlowWork(state, target == null ? null : toRva(target, state.imageBase));
    } else if (
      state.iced.FlowControl["IndirectBranch"] === instr.flowControl ||
      state.iced.FlowControl["Return"] === instr.flowControl ||
      state.iced.FlowControl["Interrupt"] === instr.flowControl
    ) {
      break;
    }
    const nextRva = toRva(instr.nextIP, state.imageBase);
    if (nextRva == null) break;
    const nextDecoderEntry = getDecoderForRva(state.decoders, nextRva);
    if (!nextDecoderEntry || nextDecoderEntry !== decoderEntry) break;
    if (state.yieldEveryInstructions && state.instructionCount % state.yieldEveryInstructions === 0) {
      await state.onYield?.(snapshot(state));
    }
  }
};

/**
 * Control-flow guided decoder used for instruction-set feature sampling.
 *
 * Key idea: avoid linear "decode everything" to reduce false positives from data regions.
 *
 * Traversal rules (to keep this maintainable, these are the semantics we rely on):
 * - Decode sequentially inside a single section until:
 *   - `RET` / `JMP [reg|mem]` / other dynamic control-flow => stop (target is unknown).
 *   - Invalid instruction => stop (likely not code bytes).
 *   - Unconditional near jump => enqueue jump target and stop current linear run.
 *   - End of section => stop (we do not cross section boundaries).
 * - Conditional near jump => enqueue branch target and continue decoding fallthrough.
 * - Near `CALL` => enqueue call target and continue decoding fallthrough.
 *   We do not try to "follow RET back to the caller": the return address is taken from the stack
 *   and is not statically knowable. Continuing after `CALL` is enough to cover the common case
 *   (return to next instruction).
 */
export async function disassembleControlFlowForInstructionSets(opts: {
  iced: IcedX86Module;
  bitness: 32 | 64;
  imageBase: bigint;
  sections: DisassemblySection[];
  entrypoints: number[];
  yieldEveryInstructions: number;
  featureCounts: Map<number, number>;
  issues: string[];
  signal?: AbortSignal;
  onYield?: (snapshot: DisassemblyYieldSnapshot) => Promise<void>;
}): Promise<DisassemblyYieldSnapshot> {
  const bytesSampled = opts.sections.reduce((sum, entry) => sum + entry.data.length, 0);
  const decoders = opts.sections.map(entry => ({
    ...entry,
    decoder: new opts.iced.Decoder(opts.bitness, entry.data, opts.iced.DecoderOptions.None)
  }));

  let decodeStopIssuesLogged = 0;
  let decodeStopIssuesSuppressed = 0;
  const recordDecodeStopIssue = (message: string): void => {
    if (decodeStopIssuesLogged < MAX_DECODE_STOP_ISSUES) {
      opts.issues.push(message);
      decodeStopIssuesLogged += 1;
    } else {
      decodeStopIssuesSuppressed += 1;
    }
  };

  const visited = new Set<number>();
  const queued = new Set<number>();
  const queue = [...opts.entrypoints].reverse();
  for (const rva of queue) {
    queued.add(rva >>> 0);
  }

  const state: ControlFlowDecodeState = {
    iced: opts.iced,
    imageBase: opts.imageBase,
    bytesSampled,
    decoders,
    visited,
    queued,
    queue,
    featureCounts: opts.featureCounts,
    yieldEveryInstructions: opts.yieldEveryInstructions,
    ...(opts.signal ? { signal: opts.signal } : {}),
    ...(opts.onYield ? { onYield: opts.onYield } : {}),
    bytesDecoded: 0,
    instructionCount: 0,
    invalidInstructionCount: 0,
    recordDecodeStopIssue
  };

  const instr = new opts.iced.Instruction();
  try {
    while (queue.length > 0) {
      if (opts.signal?.aborted) break;

      const startRva = queue.pop();
      if (startRva == null) break;
      queued.delete(startRva);
      const decoderEntry = getDecoderForRva(decoders, startRva);
      if (!decoderEntry) continue;
      await decodeLinearRun(state, decoderEntry, startRva, instr);
    }
    return snapshot(state);
  } finally {
    if (decodeStopIssuesSuppressed > 0) {
      opts.issues.push(
        `Additional ${decodeStopIssuesSuppressed} decode stop(s) omitted; showing first ${MAX_DECODE_STOP_ISSUES}.`
      );
    }
    safeFree(instr);
    for (const entry of decoders) {
      safeFree(entry.decoder);
    }
  }
}
