"use strict";

import type { AnalyzePeEntrypointDisassemblyOptions } from "../types.js";
import type { MappedCodeBlock } from "./code-bytes.js";
import { toRva } from "./control-flow.js";
import type { IcedInstructionObject, IcedModule } from "./iced.js";

export type GuardFallthrough = {
  kind: "current-block";
  rva: number;
};

const canContinueInBlock = (mapped: MappedCodeBlock, rva: number): boolean => {
  const offset = rva - mapped.rvaStart;
  return offset >= 0 && offset < mapped.data.length;
};

const guardFunctionPointerRvas = (
  opts: AnalyzePeEntrypointDisassemblyOptions
): Set<number> => {
  const loadcfg = opts.loadcfg;
  const rvas = new Set<number>();
  if (!loadcfg) return rvas;
  for (const address of [
    loadcfg.GuardCFCheckFunctionPointer,
    loadcfg.GuardCFDispatchFunctionPointer
  ]) {
    const rva = toRva(address, opts.imageBase);
    if (rva != null) rvas.add(rva);
  }
  return rvas;
};

export const getGuardFallthrough = (
  iced: IcedModule,
  opts: AnalyzePeEntrypointDisassemblyOptions,
  mapped: MappedCodeBlock,
  instruction: IcedInstructionObject
): GuardFallthrough | null => {
  if (instruction.flowControl !== iced.FlowControl["IndirectCall"]) return null;
  if (instruction.op0Kind !== iced.OpKind["Memory"]) return null;
  const slotRva = toRva(instruction.memoryDisplacement, opts.imageBase);
  if (slotRva == null || !guardFunctionPointerRvas(opts).has(slotRva)) return null;
  const fallthroughRva = toRva(instruction.nextIP, opts.imageBase);
  return fallthroughRva != null && canContinueInBlock(mapped, fallthroughRva)
    ? { kind: "current-block", rva: fallthroughRva }
    : null;
};
