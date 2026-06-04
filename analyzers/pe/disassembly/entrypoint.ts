"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import { isIcedX86Module, type IcedX86Module } from "../../x86/disassembly-iced.js";
import { loadIcedX86 } from "#iced-x86-loader";
import type {
  AnalyzePeEntrypointDisassemblyOptions,
  PeEntrypointDisassemblyBlock,
  PeEntrypointDisassemblyBlockKind,
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
  getDirectControlFlowTarget,
  getImportTarget,
  toRva,
  type DirectControlFlowTarget
} from "./entrypoint-control-flow.js";
import { buildImportTargetMap, type ImportTarget } from "./entrypoint-import-targets.js";

type IcedInstruction = InstanceType<IcedX86Module["Instruction"]>;
type IcedFormatter = { format(instruction: IcedInstruction): string; free(): void };
type EntrypointIcedModule = IcedX86Module & {
  Formatter: new (syntax: number) => IcedFormatter;
  FormatterSyntax: { Nasm: number };
};
type IcedLoader = () => Promise<unknown>;
type PendingBlock = {
  kind: PeEntrypointDisassemblyBlockKind;
  mapped: MappedCodeBlock;
  sourceInstructionRva?: number;
};
type DecodeState = {
  blocks: PeEntrypointDisassemblyBlock[];
  bytesDecoded: number;
  instructionCount: number;
  previewLimitLogged: boolean;
  visitedBlocks: Set<number>;
  queuedBlocks: Set<number>;
};

// UI preview caps: enough for entry stubs/prologues while avoiding accidental whole-file sweeps.
const ENTRYPOINT_PREVIEW_INSTRUCTION_LIMIT = 64;
const ENTRYPOINT_PREVIEW_BLOCK_LIMIT = 4;

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null;

const isEntrypointIcedModule = (value: unknown): value is EntrypointIcedModule => {
  if (!isRecord(value) || !isIcedX86Module(value)) return false;
  const module = value as IcedX86Module & Record<string, unknown>;
  const formatterSyntax = module["FormatterSyntax"];
  return (
    isRecord(formatterSyntax) &&
    typeof formatterSyntax["Nasm"] === "number" &&
    typeof module["Formatter"] === "function"
  );
};

const safeFree = (resource: { free(): void } | null | undefined): void => {
  if (!resource) return;
  try {
    resource.free();
  } catch {
    // iced-x86 cleanup is best-effort; cleanup failures must not hide analysis notes.
  }
};

const canQueueBlock = (
  state: DecodeState,
  pending: PendingBlock[],
  rva: number
): boolean => {
  if (state.visitedBlocks.has(rva) || state.queuedBlocks.has(rva)) return true;
  return state.blocks.length + pending.length < ENTRYPOINT_PREVIEW_BLOCK_LIMIT;
};

const queueFollowedBlock = async (
  reader: FileRangeReader,
  opts: AnalyzePeEntrypointDisassemblyOptions,
  state: DecodeState,
  pending: PendingBlock[],
  follow: DirectControlFlowTarget,
  instructionRva: number,
  issues: string[]
): Promise<boolean> => {
  if (state.visitedBlocks.has(follow.rva) || state.queuedBlocks.has(follow.rva)) return true;
  if (!canQueueBlock(state, pending, follow.rva)) {
    issues.push(`Entrypoint preview capped at ${ENTRYPOINT_PREVIEW_BLOCK_LIMIT} code blocks.`);
    return false;
  }
  const mapped = await loadCodeBytes(reader, opts, follow.rva, issues, "Control-flow target");
  if (!mapped) return false;
  pending.push({ kind: follow.kind, mapped, sourceInstructionRva: instructionRva });
  state.queuedBlocks.add(follow.rva);
  return true;
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
  block: PendingBlock,
  formatter: IcedFormatter,
  importTargets: Map<number, ImportTarget>,
  state: DecodeState,
  pending: PendingBlock[],
  issues: string[]
): Promise<PeEntrypointDisassemblyBlock> => {
  const decoder = new iced.Decoder(opts.is64Bit ? 64 : 32, block.mapped.data, iced.DecoderOptions.None);
  const instr = new iced.Instruction();
  const instructions: PeEntrypointInstruction[] = [];
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
      const text = formatter.format(instr);
      const instruction: PeEntrypointInstruction = {
        rva,
        fileOffset: block.mapped.fileOffsetStart + offsetInPreview,
        text
      };
      if (importTarget) instruction.target = importTarget;
      if (!importTarget && directTarget) {
        const followed = await queueFollowedBlock(
          reader,
          opts,
          state,
          pending,
          directTarget,
          rva,
          issues
        );
        instruction.target = { kind: "code", rva: directTarget.rva, followed };
      }
      instructions.push(instruction);
      state.bytesDecoded += instr.length;
      state.instructionCount += 1;
      if (instr.flowControl !== iced.FlowControl["Next"]) {
        if (importTarget) {
          issues.push(`Entrypoint preview stopped at imported target '${importTarget.label}'.`);
        } else if (directTarget && instruction.target?.kind === "code" && instruction.target.followed) {
          issues.push(`Entrypoint preview followed ${directTarget.kind.replace("followed-", "")} target.`);
        } else {
          issues.push(`Entrypoint preview stopped at control-flow instruction '${text}'.`);
        }
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
  const pending: PendingBlock[] = [{ kind: "entrypoint", mapped }];
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
