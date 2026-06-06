"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import { loadIcedX86 } from "#iced-x86-loader";
import type {
  AnalyzePeEntrypointDisassemblyOptions,
  PeEntrypointDisassemblyBlock,
  PeEntrypointDisassemblyReport,
  PeEntrypointInstruction
} from "./types.js";
import {
  type ValidEntrypointMetadata,
  emptyEntrypointReport,
  validateEntrypointMetadata
} from "./entrypoint-metadata.js";
import { loadCodeBytes, type MappedCodeBlock } from "./entrypoint-code-bytes.js";
import {
  getConditionalBranchTargets,
  getDirectControlFlowTarget,
  getImportTarget,
  toRva
} from "./entrypoint-control-flow.js";
import { buildImportTargetMap, type ImportTarget } from "./entrypoint-import-targets.js";
import { getReturningImportFallthrough } from "./entrypoint-import-fallthrough.js";
import { followDirectCodeTarget } from "./entrypoint-direct-target.js";
import { createEntrypointInstruction, createEntrypointNoteState } from "./entrypoint-instruction.js";
import {
  ENTRYPOINT_PREVIEW_BLOCK_LIMIT,
  queueConditionalBranch,
  queueFollowedBlock,
  type PendingEntrypointBlock
} from "./entrypoint-follow-queue.js";
import {
  isEntrypointIcedModule,
  type EntrypointIcedModule,
  type IcedFormatter
} from "./entrypoint-iced.js";

type IcedLoader = () => Promise<unknown>;
type DecodeState = {
  blocks: PeEntrypointDisassemblyBlock[];
  bytesDecoded: number;
  instructionCount: number;
  previewLimitLogged: boolean;
  visitedBlocks: Set<number>;
  queuedBlocks: Set<number>;
};

// UI preview caps: enough for entry stubs/prologues while avoiding accidental whole-file sweeps.
const ENTRYPOINT_PREVIEW_INSTRUCTION_LIMIT = 256;

const safeFree = (resource: { free(): void } | null | undefined): void => {
  if (!resource) return;
  try {
    resource.free();
  } catch {
    // iced-x86 cleanup is best-effort; cleanup failures must not hide analysis notes.
  }
};

const logPreviewLimit = (state: DecodeState, issues: string[]): void => {
  if (state.previewLimitLogged) return;
  state.previewLimitLogged = true;
  issues.push(`Entrypoint preview capped at ${ENTRYPOINT_PREVIEW_INSTRUCTION_LIMIT} instructions.`);
};

const decodeBlock = async (
  reader: FileRangeReader,
  iced: EntrypointIcedModule,
  opts: AnalyzePeEntrypointDisassemblyOptions,
  block: PendingEntrypointBlock,
  formatter: IcedFormatter,
  importTargets: Map<number, ImportTarget>,
  state: DecodeState,
  pending: PendingEntrypointBlock[],
  issues: string[]
): Promise<PeEntrypointDisassemblyBlock> => {
  const decoder = new iced.Decoder(opts.is64Bit ? 64 : 32, block.mapped.data, iced.DecoderOptions.None);
  const instr = new iced.Instruction();
  const instructions: PeEntrypointInstruction[] = [];
  const noteState = createEntrypointNoteState();
  let recordedStopReason = false;
  try {
    decoder.position = 0;
    decoder.ip = BigInt.asUintN(64, opts.imageBase + BigInt(block.mapped.rvaStart));
    while (decoder.canDecode && state.instructionCount < ENTRYPOINT_PREVIEW_INSTRUCTION_LIMIT) {
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
      const importTarget = getImportTarget(iced, opts, instr, importTargets);
      const directTarget = getDirectControlFlowTarget(iced, opts, instr);
      const branchTargets = getConditionalBranchTargets(iced, opts, instr);
      const importFallthrough = getReturningImportFallthrough(
        iced,
        opts,
        block.mapped,
        instr,
        importTarget,
        block.returnRva
      );
      const instruction = createEntrypointInstruction(
        iced,
        instr,
        formatter,
        rva,
        block.mapped.fileOffsetStart + offsetInPreview,
        noteState
      );
      if (importTarget) {
        const returnFollowed = importFallthrough?.kind === "source-call"
          ? await queueFollowedBlock(
            reader,
            opts,
            state,
            pending,
            { kind: "followed-import-return", rva: importFallthrough.rva },
            rva,
            issues
          )
          : importFallthrough?.kind === "current-block";
        instruction.target = importFallthrough == null
          ? importTarget
          : { ...importTarget, returnRva: importFallthrough.rva, returnFollowed };
      }
      if (!importTarget && directTarget) {
        instruction.target = await followDirectCodeTarget(
          reader,
          opts,
          state,
          pending,
          directTarget,
          rva,
          instr.nextIP,
          issues
        );
      }
      if (!importTarget && !directTarget && branchTargets) {
        const followed = await queueConditionalBranch(
          reader,
          opts,
          state,
          pending,
          branchTargets,
          rva,
          issues
        );
        instruction.target = {
          kind: "branch",
          branchRva: branchTargets.branch.rva,
          branchFollowed: followed.branchFollowed,
          fallthroughRva: branchTargets.fallthrough.rva,
          fallthroughFollowed: followed.fallthroughFollowed
        };
      }
      instructions.push(instruction);
      state.bytesDecoded += instr.length;
      state.instructionCount += 1;
      if (instr.flowControl !== iced.FlowControl["Next"]) {
        if (importTarget && instruction.target?.kind === "import" && instruction.target.returnFollowed) {
          issues.push(`Entrypoint preview continued after returning import '${importTarget.label}'.`);
        } else if (importTarget) {
          issues.push(`Entrypoint preview stopped at imported target '${importTarget.label}'.`);
        } else if (directTarget && instruction.target?.kind === "code" && instruction.target.followed) {
          const maybeSpeculative = instruction.target.fallthroughKind === "speculative-call-return"
            ? " and speculative call fallthrough"
            : "";
          issues.push(
            `Entrypoint preview followed ${directTarget.kind.replace("followed-", "")} ` +
            `target${maybeSpeculative}.`
          );
        } else if (instruction.target?.kind === "branch") {
          issues.push("Entrypoint preview followed conditional branch target(s).");
        } else {
          issues.push(`Entrypoint preview stopped at control-flow instruction '${instruction.text}'.`);
        }
        if (importFallthrough?.kind === "current-block") continue;
        recordedStopReason = true;
        break;
      }
    }
    if (state.instructionCount >= ENTRYPOINT_PREVIEW_INSTRUCTION_LIMIT && decoder.canDecode) {
      logPreviewLimit(state, issues);
    } else if (!recordedStopReason && instructions.length > 0 && !decoder.canDecode) {
      issues.push("Entrypoint preview stopped at the readable byte boundary.");
    }
    return {
      kind: block.kind,
      startRva: block.mapped.rvaStart,
      fileOffsetStart: block.mapped.fileOffsetStart,
      ...(block.sourceInstructionRva != null ? { sourceInstructionRva: block.sourceInstructionRva } : {}),
      instructions
    };
  } finally {
    safeFree(instr);
    safeFree(decoder);
  }
};

const decodeEntrypointPreview = async (
  reader: FileRangeReader,
  iced: EntrypointIcedModule,
  opts: AnalyzePeEntrypointDisassemblyOptions,
  metadata: ValidEntrypointMetadata,
  mapped: MappedCodeBlock,
  issues: string[]
): Promise<Pick<PeEntrypointDisassemblyReport, "blocks" | "bytesDecoded" | "instructionCount">> => {
  const formatter = new iced.Formatter(iced.FormatterSyntax.Nasm);
  const importTargets = buildImportTargetMap(opts, metadata);
  const state: DecodeState = {
    blocks: [],
    bytesDecoded: 0,
    instructionCount: 0,
    previewLimitLogged: false,
    visitedBlocks: new Set(),
    queuedBlocks: new Set([mapped.rvaStart])
  };
  const pending: PendingEntrypointBlock[] = [{ kind: "entrypoint", mapped }];
  try {
    while (pending.length > 0 && state.blocks.length < ENTRYPOINT_PREVIEW_BLOCK_LIMIT) {
      const block = pending.shift();
      if (!block) break;
      state.queuedBlocks.delete(block.mapped.rvaStart);
      if (state.visitedBlocks.has(block.mapped.rvaStart)) continue;
      state.visitedBlocks.add(block.mapped.rvaStart);
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
      if (state.instructionCount >= ENTRYPOINT_PREVIEW_INSTRUCTION_LIMIT) break;
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

export async function analyzePeEntrypointDisassembly(
  reader: FileRangeReader,
  opts: AnalyzePeEntrypointDisassemblyOptions,
  loader: IcedLoader = loadIcedX86
): Promise<PeEntrypointDisassemblyReport> {
  const issues: string[] = [];
  const metadata = validateEntrypointMetadata(opts, issues);
  if (!metadata) return emptyEntrypointReport(opts, issues);
  let mapped: MappedCodeBlock | null;
  try {
    mapped = await loadCodeBytes(reader, opts, metadata.entrypointRva, issues, "Entry point");
  } catch (error) {
    issues.push(`Entrypoint byte loading failed (${String(error)})`);
    return emptyEntrypointReport(opts, issues);
  }
  if (!mapped) return emptyEntrypointReport(opts, issues);
  if (mapped.data.length === 0) {
    issues.push("No file bytes are available at the mapped entry point.");
    return emptyEntrypointReport(opts, issues);
  }
  let loaded: unknown;
  try {
    loaded = await loader();
  } catch (error) {
    issues.push(`Failed to load iced-x86 disassembler (${String(error)})`);
    return emptyEntrypointReport(opts, issues);
  }
  if (!isEntrypointIcedModule(loaded)) {
    issues.push("Failed to load iced-x86 disassembler (unexpected module shape).");
    return emptyEntrypointReport(opts, issues);
  }
  try {
    return {
      bitness: metadata.bitness,
      entrypointRva: metadata.entrypointRva,
      ...(await decodeEntrypointPreview(reader, loaded, opts, metadata, mapped, issues)),
      issues
    };
  } catch (error) {
    issues.push(`Entrypoint disassembly failed (${String(error)})`);
    return emptyEntrypointReport(opts, issues);
  }
}
