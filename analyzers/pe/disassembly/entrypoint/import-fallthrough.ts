"use strict";

import type { AnalyzePeEntrypointDisassemblyOptions } from "../types.js";
import type { MappedCodeBlock } from "./code-bytes.js";
import { toRva } from "./control-flow.js";
import type { ImportTarget } from "./import-targets.js";
import type { IcedInstructionObject, IcedModule } from "./iced.js";
import { isKnownNonReturningImport } from "./non-returning-imports.js";
import { getStackReturnTarget } from "./call-stack.js";
import type { EmulationState } from "./emulation/state.js";

export type ReturningImportFallthrough =
  | {
      kind: "current-block";
      rva: number;
    }
  | {
      kind: "stack-return";
      rva: number;
    };

const canContinueInBlock = (mapped: MappedCodeBlock, rva: number): boolean => {
  const offset = rva - mapped.rvaStart;
  return offset >= 0 && offset < mapped.data.length;
};

export const getReturningImportFallthrough = (
  iced: IcedModule,
  opts: AnalyzePeEntrypointDisassemblyOptions,
  mapped: MappedCodeBlock,
  instruction: IcedInstructionObject,
  importTarget: ImportTarget | null,
  emulationState: EmulationState
): ReturningImportFallthrough | null => {
  if (!importTarget) return null;
  if (isKnownNonReturningImport(importTarget.label)) return null;
  if (instruction.flowControl === iced.FlowControl["IndirectBranch"]) {
    const target = getStackReturnTarget(iced, opts, emulationState);
    return target.kind === "known" ? { kind: "stack-return", rva: target.rva } : null;
  }
  if (instruction.flowControl !== iced.FlowControl["IndirectCall"]) return null;
  const fallthroughRva = toRva(instruction.nextIP, opts.imageBase);
  return fallthroughRva != null && canContinueInBlock(mapped, fallthroughRva)
    ? { kind: "current-block", rva: fallthroughRva }
    : null;
};
