"use strict";

import type { AnalyzePeEntrypointDisassemblyOptions } from "../types.js";
import type { MappedCodeBlock } from "./code-bytes.js";
import { toRva } from "./control-flow.js";
import type { IcedInstructionObject, IcedModule } from "./iced.js";

export type IndirectCallFallthrough = {
  kind: "current-block";
  rva: number;
};

const canContinueInBlock = (mapped: MappedCodeBlock, rva: number): boolean => {
  const offset = rva - mapped.rvaStart;
  return offset >= 0 && offset < mapped.data.length;
};

export const getUnknownIndirectCallFallthrough = (
  iced: IcedModule,
  opts: AnalyzePeEntrypointDisassemblyOptions,
  mapped: MappedCodeBlock,
  instruction: IcedInstructionObject
): IndirectCallFallthrough | null => {
  if (instruction.flowControl !== iced.FlowControl["IndirectCall"]) return null;
  const fallthroughRva = toRva(instruction.nextIP, opts.imageBase);
  return fallthroughRva != null && canContinueInBlock(mapped, fallthroughRva)
    ? { kind: "current-block", rva: fallthroughRva }
    : null;
};
