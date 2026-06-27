"use strict";

import type { IcedX86Module } from "./disassembly-iced.js";
import { getNearBranchTarget } from "./disassembly-branch-targets.js";

type DisassemblySectionVaddr = {
  vaddrStart: bigint;
  data: Uint8Array<ArrayBufferLike>;
};

type DisassemblyYieldSnapshot = {
  bytesDecoded: number;
  instructionCount: number;
  invalidInstructionCount: number;
};

type DisassemblyDecoderEntryVaddr = DisassemblySectionVaddr & {
  decoder: InstanceType<IcedX86Module["Decoder"]>;
};

type ControlFlowDecodeStateVaddr = {
  iced: IcedX86Module;
  bytesSampled: number;
  decoders: DisassemblyDecoderEntryVaddr[];
  visited: Set<bigint>;
  queued: Set<bigint>;
  queue: bigint[];
  featureCounts: Map<number, number>;
  yieldEveryInstructions: number;
  signal?: AbortSignal;
  onYield?: (snapshot: DisassemblyYieldSnapshot) => Promise<void>;
  bytesDecoded: number;
  instructionCount: number;
  invalidInstructionCount: number;
  recordDecodeStopIssue(message: string): void;
};

const MAX_DECODE_STOP_ISSUES = 200;

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

const tryGetOffsetInSection = (vaddr: bigint, section: DisassemblySectionVaddr): number | null => {
  const end = section.vaddrStart + BigInt(section.data.length);
  if (vaddr < section.vaddrStart || vaddr >= end) return null;
  const delta = vaddr - section.vaddrStart;
  const offset = Number(delta);
  if (!Number.isSafeInteger(offset) || offset < 0 || offset >= section.data.length) return null;
  return offset;
};

const snapshot = (state: ControlFlowDecodeStateVaddr): DisassemblyYieldSnapshot => ({
  bytesDecoded: state.bytesDecoded,
  instructionCount: state.instructionCount,
  invalidInstructionCount: state.invalidInstructionCount
});

const getDecoderForVaddr = (
  decoders: DisassemblyDecoderEntryVaddr[],
  vaddr: bigint
): DisassemblyDecoderEntryVaddr | null => {
  for (const entry of decoders) {
    if (tryGetOffsetInSection(vaddr, entry) != null) return entry;
  }
  return null;
};

const addControlFlowWork = (state: ControlFlowDecodeStateVaddr, vaddr: bigint | null): void => {
  if (vaddr == null) return;
  if (state.visited.has(vaddr) || state.queued.has(vaddr)) return;
  if (!getDecoderForVaddr(state.decoders, vaddr)) return;
  state.queue.push(vaddr);
  state.queued.add(vaddr);
};

const countInstructionFeatures = (
  state: ControlFlowDecodeStateVaddr,
  instr: InstanceType<IcedX86Module["Instruction"]>
): void => {
  const features = instr.cpuidFeatures();
  for (const feature of features) {
    state.featureCounts.set(feature, (state.featureCounts.get(feature) || 0) + 1);
  }
};

const decodeLinearRun = async (
  state: ControlFlowDecodeStateVaddr,
  decoderEntry: DisassemblyDecoderEntryVaddr,
  startVaddr: bigint,
  instr: InstanceType<IcedX86Module["Instruction"]>
): Promise<void> => {
  const offset = tryGetOffsetInSection(startVaddr, decoderEntry);
  if (offset == null) return;
  const decoder = decoderEntry.decoder;
  decoder.position = offset;
  decoder.ip = BigInt.asUintN(64, startVaddr);
  while (decoder.canDecode) {
    if (state.signal?.aborted) return;
    decoder.decodeOut(instr);
    const instrVaddr = BigInt.asUintN(64, instr.ip);
    if (state.visited.has(instrVaddr)) break;
    state.visited.add(instrVaddr);
    state.instructionCount += 1;
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
      state.recordDecodeStopIssue(`Stopping at an invalid instruction at address 0x${instrVaddr.toString(16)}.`);
      break;
    }
    if (!isUd2Trap) countInstructionFeatures(state, instr);
    if (state.iced.FlowControl["UnconditionalBranch"] === instr.flowControl) {
      const target = getNearBranchTarget(instr, state.iced.OpKind);
      addControlFlowWork(state, target == null ? null : BigInt.asUintN(64, target));
      break;
    }
    if (
      state.iced.FlowControl["ConditionalBranch"] === instr.flowControl ||
      state.iced.FlowControl["Call"] === instr.flowControl ||
      state.iced.FlowControl["XbeginXabortXend"] === instr.flowControl
    ) {
      const target = getNearBranchTarget(instr, state.iced.OpKind);
      addControlFlowWork(state, target == null ? null : BigInt.asUintN(64, target));
    } else if (
      state.iced.FlowControl["IndirectBranch"] === instr.flowControl ||
      state.iced.FlowControl["Return"] === instr.flowControl ||
      state.iced.FlowControl["Interrupt"] === instr.flowControl
    ) {
      break;
    }
    const nextVaddr = BigInt.asUintN(64, instr.nextIP);
    const nextDecoderEntry = getDecoderForVaddr(state.decoders, nextVaddr);
    if (!nextDecoderEntry || nextDecoderEntry !== decoderEntry) break;
    if (state.yieldEveryInstructions && state.instructionCount % state.yieldEveryInstructions === 0) {
      await state.onYield?.(snapshot(state));
    }
  }
};

/**
 * Control-flow guided decoder used for instruction-set feature sampling (ELF-style vaddr mapping).
 *
 * This version does not rely on a 32-bit RVA space and can operate on full 64-bit virtual addresses
 * as long as the decoded addresses still map back into one of the sampled byte ranges.
 */
export async function disassembleControlFlowForInstructionSetsVaddr(opts: {
  iced: IcedX86Module;
  bitness: 32 | 64;
  sections: DisassemblySectionVaddr[];
  entrypoints: bigint[];
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

  const visited = new Set<bigint>();
  const queued = new Set<bigint>();
  const queue = [...opts.entrypoints].reverse();
  for (const vaddr of queue) {
    queued.add(vaddr);
  }

  const state: ControlFlowDecodeStateVaddr = {
    iced: opts.iced,
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

      const startVaddr = queue.pop();
      if (startVaddr == null) break;
      queued.delete(startVaddr);

      const decoderEntry = getDecoderForVaddr(decoders, startVaddr);
      if (!decoderEntry) continue;
      await decodeLinearRun(state, decoderEntry, startVaddr, instr);
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

