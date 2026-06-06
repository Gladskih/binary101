"use strict";

import type { FileRangeReader } from "../../../file-range-reader.js";
import type {
  AnalyzePeEntrypointDisassemblyOptions,
  PeEntrypointDisassemblyBlock,
  PeEntrypointDisassemblyReport,
  PeEntrypointInstruction
} from "../types.js";
import type { ValidMetadata } from "./metadata.js";
import type { MappedCodeBlock } from "./code-bytes.js";
import { toRva } from "./control-flow.js";
import { buildImportTargetMap, type ImportTarget } from "./import-targets.js";
import { createInstruction } from "./instruction.js";
import { createEmulationState } from "./emulation.js";
import { applyInstructionTargets, controlFlowIssue } from "./targeting.js";
import {
  createBlockKey,
  type FollowQueueState,
  type PendingBlock
} from "./follow-queue.js";
import type { IcedFormatter, IcedModule } from "./iced.js";

type DecodeState = FollowQueueState & {
  bytesDecoded: number;
  instructionCount: number;
};

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
  state: DecodeState,
  pending: PendingBlock[],
  issues: string[]
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
        issues.push("Entrypoint preview stopped at an invalid or zero-length instruction.");
        recordedStopReason = true;
        break;
      }
      const offsetInPreview = rva - block.mapped.rvaStart;
      if (offsetInPreview < 0 || instr.length > block.mapped.data.length - offsetInPreview) {
        issues.push("Entrypoint preview stopped at the readable byte boundary.");
        recordedStopReason = true;
        break;
      }
      const instruction = createInstruction(
        iced,
        instr,
        formatter,
        rva,
        block.mapped.fileOffsetStart + offsetInPreview,
        block.emulationState
      );
      const targets = await applyInstructionTargets(
        reader,
        iced,
        opts,
        block,
        instr,
        instruction,
        importTargets,
        rva,
        state,
        pending,
        issues
      );
      instructions.push(instruction);
      state.bytesDecoded += instr.length;
      state.instructionCount += 1;
      if (instr.flowControl !== iced.FlowControl["Next"]) {
        issues.push(controlFlowIssue(instruction, targets));
        if (targets.importFallthrough?.kind === "current-block") continue;
        recordedStopReason = true;
        break;
      }
    }
    if (!recordedStopReason && instructions.length > 0 && !decoder.canDecode) {
      issues.push("Entrypoint preview stopped at the readable byte boundary.");
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
  const entryState = createEmulationState(metadata.bitness);
  const entryKey = createBlockKey(mapped.rvaStart, entryState);
  const state: DecodeState = {
    blocks: [],
    bytesDecoded: 0,
    instructionCount: 0,
    visitedBlocks: new Set(),
    queuedBlocks: new Set([entryKey]),
    contextKeysByRva: new Map([[mapped.rvaStart, new Set([entryKey])]]),
    contextLimitReportedRvas: new Set()
  };
  const pending: PendingBlock[] = [{
    kind: "entrypoint",
    mapped,
    emulationState: entryState,
    key: entryKey
  }];
  try {
    while (pending.length > 0) {
      const block = pending.shift();
      if (!block) break;
      state.queuedBlocks.delete(block.key);
      if (state.visitedBlocks.has(block.key)) continue;
      state.visitedBlocks.add(block.key);
      const decoded = await decodeBlock(
        reader,
        iced,
        opts,
        block,
        formatter,
        importTargets,
        state,
        pending,
        issues
      );
      if (decoded.instructions.length) state.blocks.push(decoded);
    }
    return {
      blocks: state.blocks,
      bytesDecoded: state.bytesDecoded,
      instructionCount: state.instructionCount
    };
  } finally {
    safeFree(formatter);
  }
};
