"use strict";

import type {
  PeEntrypointDisassemblyBlock,
  PeEntrypointInstruction,
  PeEntrypointInstructionTarget
} from "../../analyzers/pe/disassembly/index.js";

export type PeEntrypointRenderBlock = {
  block: PeEntrypointDisassemblyBlock;
  duplicateCount: number;
  sources: number[];
};

type SignatureScalar = string | number | boolean | null;
type TargetSignature = Record<string, SignatureScalar> | null;
type InstructionSignature = {
  rva: number;
  fileOffset: number;
  text: string;
  notes: string[];
  target: TargetSignature;
};

export const visibleEntrypointBlocks = (
  blocks: readonly PeEntrypointDisassemblyBlock[]
): PeEntrypointRenderBlock[] => {
  const out: PeEntrypointRenderBlock[] = [];
  const bySignature = new Map<string, PeEntrypointRenderBlock>();
  for (const block of blocks) {
    const signature = blockSignature(block);
    const existing = bySignature.get(signature);
    if (existing) {
      existing.duplicateCount += 1;
      existing.sources = uniqueSourceRvas(existing, block.sourceInstructionRva);
    } else {
      const rendered = {
        block,
        duplicateCount: 1,
        sources: block.sourceInstructionRva == null ? [] : [block.sourceInstructionRva]
      };
      bySignature.set(signature, rendered);
      out.push(rendered);
    }
  }
  return out;
};

const targetSignature = (target: PeEntrypointInstructionTarget | undefined): TargetSignature => {
  if (!target) return null;
  if (target.kind === "code") return { kind: target.kind, rva: target.rva };
  if (target.kind === "return") {
    return "rva" in target
      ? { kind: target.kind, rva: target.rva }
      : { kind: target.kind, reason: target.reason };
  }
  if (target.kind === "branch") {
    return { kind: target.kind, branchRva: target.branchRva, fallthroughRva: target.fallthroughRva };
  }
  return {
    kind: target.kind,
    label: target.label,
    slotRva: target.slotRva,
    importKind: target.importKind,
    guardIatEntry: target.guardIatEntry,
    returnRva: target.returnRva ?? null
  };
};

const instructionSignature = (instruction: PeEntrypointInstruction): InstructionSignature => ({
  rva: instruction.rva,
  fileOffset: instruction.fileOffset,
  text: instruction.text,
  notes: instruction.notes ?? [],
  target: targetSignature(instruction.target)
});

const blockSignature = (block: PeEntrypointDisassemblyBlock): string =>
  JSON.stringify({
    kind: block.kind,
    startRva: block.startRva,
    fileOffsetStart: block.fileOffsetStart,
    instructions: block.instructions.map(instructionSignature)
  });

const uniqueSourceRvas = (
  block: PeEntrypointRenderBlock,
  sourceRva: number | undefined
): number[] =>
  sourceRva == null || block.sources.includes(sourceRva)
    ? block.sources
    : [...block.sources, sourceRva];
