"use strict";

import type { IcedX86Module } from "../../x86/disassembly-iced.js";
import type { AnalyzePeEntrypointDisassemblyOptions } from "./types.js";
import type { MappedCodeBlock } from "./entrypoint-code-bytes.js";
import { toRva } from "./entrypoint-control-flow.js";
import type { ImportTarget } from "./entrypoint-import-targets.js";
import { isKnownReturningImport } from "./entrypoint-returning-imports.js";

type IcedInstruction = InstanceType<IcedX86Module["Instruction"]>;

export type ReturningImportFallthrough =
  | {
      kind: "current-block";
      rva: number;
    }
  | {
      kind: "source-call";
      rva: number;
    };

const canContinueInBlock = (mapped: MappedCodeBlock, rva: number): boolean => {
  const offset = rva - mapped.rvaStart;
  return offset >= 0 && offset < mapped.data.length;
};

export const getReturningImportFallthrough = (
  iced: IcedX86Module,
  opts: AnalyzePeEntrypointDisassemblyOptions,
  mapped: MappedCodeBlock,
  instruction: IcedInstruction,
  importTarget: ImportTarget | null,
  sourceCallReturnRva?: number
): ReturningImportFallthrough | null => {
  if (!importTarget) return null;
  if (!isKnownReturningImport(importTarget.label)) return null;
  if (instruction.flowControl === iced.FlowControl["IndirectBranch"] && sourceCallReturnRva != null) {
    return { kind: "source-call", rva: sourceCallReturnRva };
  }
  if (instruction.flowControl !== iced.FlowControl["IndirectCall"]) return null;
  const fallthroughRva = toRva(instruction.nextIP, opts.imageBase);
  return fallthroughRva != null && canContinueInBlock(mapped, fallthroughRva)
    ? { kind: "current-block", rva: fallthroughRva }
    : null;
};
