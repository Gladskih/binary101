"use strict";

import type { FileRangeReader } from "../../../file-range-reader.js";
import type {
  AnalyzePeEntrypointDisassemblyOptions,
  PeEntrypointDisassemblyBlock,
  PeEntrypointDisassemblyReport,
  PeEntrypointDisassemblyProgress,
  PeEntrypointInstruction
} from "../types.js";
import type { ValidMetadata } from "./metadata.js";
import type { MappedCodeBlock } from "./code-bytes.js";
import { toRva } from "./control-flow.js";
import { buildImportTargetMap, type ImportTarget } from "./import-targets.js";
import { createInstruction } from "./instruction.js";
import { createEmulationState, emulateInstruction } from "./emulation/index.js";
import { cloneEmulationState } from "./emulation/state.js";
import {
  invalidateTouchedMemory,
  preloadImageMemoryForInstruction
} from "./emulation/image-memory.js";
import { applyInstructionTargets, controlFlowIssue } from "./targeting.js";
import {
  createBlockKey,
  isPendingBlockCurrent,
  type FollowQueueState,
  type PendingBlock
} from "./follow-queue.js";
import { addCorrelatedState } from "./correlated-states.js";
import type { IcedFormatter, IcedModule } from "./iced.js";

type DecodeState = FollowQueueState & {
  bytesDecoded: number;
  instructionCount: number;
  yieldEveryInstructions: number;
};

const yieldToEventLoop = async (): Promise<void> =>
  new Promise<void>(resolve => setTimeout(resolve, 0));

const reportProgress = (
  opts: AnalyzePeEntrypointDisassemblyOptions,
  progress: PeEntrypointDisassemblyProgress
): void => {
  if (!opts.onProgress) return;
  try {
    opts.onProgress(progress);
  } catch {
    // UI callbacks must not abort analysis.
  }
};

const shouldYieldProgress = (state: DecodeState): boolean =>
  state.yieldEveryInstructions > 0 &&
  state.instructionCount % state.yieldEveryInstructions === 0;

const reportDecodingProgress = async (
  opts: AnalyzePeEntrypointDisassemblyOptions,
  state: DecodeState
): Promise<void> => {
  reportProgress(opts, {
    stage: "decoding",
    bytesDecoded: state.bytesDecoded,
    instructionCount: state.instructionCount,
    pendingBlockCount: state.pending.length
  });
  await yieldToEventLoop();
};

const normalizedYieldEveryInstructions = (
  opts: AnalyzePeEntrypointDisassemblyOptions
): number =>
  typeof opts.yieldEveryInstructions === "number" &&
  Number.isSafeInteger(opts.yieldEveryInstructions) &&
  opts.yieldEveryInstructions > 0
    ? opts.yieldEveryInstructions
    : 0;

const safeFree = (resource: { free(): void } | null | undefined): void => {
  if (!resource) return;
  try {
    resource.free();
  } catch {
    // iced-x86 cleanup is best-effort; cleanup failures must not hide analysis notes.
  }
};

const decodeBlock = async (
  reader: FileRangeReader,
  iced: IcedModule,
  opts: AnalyzePeEntrypointDisassemblyOptions,
  block: PendingBlock,
  formatter: IcedFormatter,
  importTargets: Map<number, ImportTarget>,
  state: DecodeState
): Promise<PeEntrypointDisassemblyBlock> => {
  const decoder = new iced.Decoder(
    opts.is64Bit ? 64 : 32,
    block.mapped.data,
    iced.DecoderOptions.None
  );
  const instr = new iced.Instruction();
  const instructions: PeEntrypointInstruction[] = [];
  let recordedStopReason = false;
  try {
    decoder.position = 0;
    decoder.ip = BigInt.asUintN(64, opts.imageBase + BigInt(block.mapped.rvaStart));
    while (decoder.canDecode) {
      decoder.decodeOut(instr);
      const rva = toRva(instr.ip, opts.imageBase);
      if (rva == null || instr.length <= 0 || instr.code === iced.Code["INVALID"]) {
        state.issues.push("Entrypoint preview stopped at an invalid or zero-length instruction.");
        recordedStopReason = true;
        break;
      }
      const offsetInPreview = rva - block.mapped.rvaStart;
      if (offsetInPreview < 0 || instr.length > block.mapped.data.length - offsetInPreview) {
        state.issues.push("Entrypoint preview stopped at the readable byte boundary.");
        recordedStopReason = true;
        break;
      }
      const instruction = createInstruction(
        iced,
        instr,
        formatter,
        rva,
        block.mapped.fileOffsetStart + offsetInPreview
      );
      const preloaded = await preloadImageMemoryForInstruction(
        reader,
        opts,
        iced,
        block.emulationState,
        instr
      );
      const emulated = emulateInstruction(iced, instr, instruction, block.emulationState);
      if (!emulated && instr.flowControl === iced.FlowControl["Next"]) {
        invalidateTouchedMemory(block.emulationState, preloaded);
      }
      const targets = await applyInstructionTargets(
        reader,
        iced,
        opts,
        state,
        block,
        instr,
        instruction,
        importTargets
      );
      instructions.push(instruction);
      state.bytesDecoded += instr.length;
      state.instructionCount += 1;
      if (shouldYieldProgress(state)) await reportDecodingProgress(opts, state);
      if (instr.flowControl !== iced.FlowControl["Next"]) {
        state.issues.push(controlFlowIssue(instruction, targets));
        if (
          targets.importFallthrough?.kind === "current-block" ||
          targets.guardFallthrough?.kind === "current-block" ||
          targets.unknownIndirectCallFallthrough?.kind === "current-block"
        ) continue;
        recordedStopReason = true;
        break;
      }
    }
    if (!recordedStopReason && instructions.length > 0 && !decoder.canDecode) {
      state.issues.push("Entrypoint preview stopped at the readable byte boundary.");
    }
    return {
      kind: block.kind,
      startRva: block.mapped.rvaStart,
      fileOffsetStart: block.mapped.fileOffsetStart,
      ...(block.sourceInstructionRva != null
        ? { sourceInstructionRva: block.sourceInstructionRva }
        : {}),
      instructions
    };
  } finally {
    safeFree(instr);
    safeFree(decoder);
  }
};

export const decodePreview = async (
  reader: FileRangeReader,
  iced: IcedModule,
  opts: AnalyzePeEntrypointDisassemblyOptions,
  metadata: ValidMetadata,
  mapped: MappedCodeBlock,
  issues: string[]
): Promise<Pick<PeEntrypointDisassemblyReport, "blocks" | "bytesDecoded" | "instructionCount">> => {
  const formatter = new iced.Formatter(iced.FormatterSyntax.Nasm);
  const importTargets = buildImportTargetMap(opts, metadata);
  // Microsoft documents that Windows x64 system calls and CRT entry/exit
  // expect DF clear; the CRT direction-flag note says string/buffer routines
  // assume the same. A local no-CRT PE32/PE32+ entrypoint probe also observed
  // DF=0 on Windows; model PE startup that way until code executes STD/CLD.
  // https://learn.microsoft.com/en-us/cpp/build/x64-software-conventions
  // https://learn.microsoft.com/en-us/cpp/c-runtime-library/direction-flag
  const entryState = createEmulationState(metadata.bitness, { DF: false });
  const entryKey = createBlockKey(mapped.rvaStart, entryState);
  const entryBlock: PendingBlock = {
    kind: "entrypoint",
    mapped,
    emulationState: entryState,
    key: entryKey
  };
  const state: DecodeState = {
    blocks: [],
    pending: [entryBlock],
    issues,
    bytesDecoded: 0,
    instructionCount: 0,
    yieldEveryInstructions: normalizedYieldEveryInstructions(opts),
    visitedBlocks: new Set(),
    emulationStatesByKey: new Map([[
      entryKey,
      addCorrelatedState(undefined, cloneEmulationState(entryState))
    ]]),
    contextKeysByRva: new Map([[mapped.rvaStart, new Set([entryKey])]]),
    precisionCostByRva: new Map([[mapped.rvaStart, 1]]),
    precisionLimitReportedRvas: new Set()
  };
  try {
    reportProgress(opts, {
      stage: "decoding",
      bytesDecoded: state.bytesDecoded,
      instructionCount: state.instructionCount,
      pendingBlockCount: state.pending.length
    });
    while (state.pending.length > 0) {
      const block = state.pending.shift();
      if (!block) break;
      if (!isPendingBlockCurrent(state, block)) continue;
      state.visitedBlocks.add(block.key);
      const decoded = await decodeBlock(
        reader,
        iced,
        opts,
        block,
        formatter,
        importTargets,
        state
      );
      if (decoded.instructions.length) state.blocks.push(decoded);
    }
    reportProgress(opts, {
      stage: "done",
      bytesDecoded: state.bytesDecoded,
      instructionCount: state.instructionCount,
      pendingBlockCount: state.pending.length
    });
    return {
      blocks: state.blocks,
      bytesDecoded: state.bytesDecoded,
      instructionCount: state.instructionCount
    };
  } finally {
    safeFree(formatter);
  }
};
