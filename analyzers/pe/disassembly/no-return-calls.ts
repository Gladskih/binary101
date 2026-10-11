"use strict";

import type { PeImportFunction } from "../imports/index.js";
import type { IcedInstructionObject, IcedX86Module } from "../../x86/disassembly-iced.js";
import { getNearBranchTarget } from "../../x86/disassembly-branch-targets.js";
import { getDirectIatReference, getIatSlotRva } from "./import-references.js";
import type { AnalyzePeInstructionSetOptions } from "./types.js";
import { normalizeRvaList, type PeDisassemblySample } from "./sampling.js";

const collectNoReturnSlots = (opts: AnalyzePeInstructionSetOptions): Set<number> => {
  const slots = new Map<number, boolean>();
  const add = (startRva: number, functions: PeImportFunction[]): void => {
    functions.forEach((fn, index) => {
      const slot = getIatSlotRva(startRva, index, opts.is64Bit ? 8 : 4);
      if (slot == null) return;
      const noReturn = (fn.apiMetadata ?? fn.winapiMetadata)?.noReturn === true;
      // Conflicting or incomplete metadata for an overlapping slot cannot prove noReturn.
      slots.set(slot, (slots.get(slot) ?? true) && noReturn);
    });
  };
  for (const entry of opts.imports?.entries ?? []) add(entry.firstThunkRva, entry.functions);
  for (const entry of opts.delayImports?.entries ?? []) add(entry.ImportAddressTableRVA, entry.functions);
  return new Set([...slots].filter(([, noReturn]) => noReturn).map(([rva]) => rva));
};

const createThunkResolver = (
  iced: IcedX86Module, opts: AnalyzePeInstructionSetOptions,
  sections: PeDisassemblySample[], slots: ReadonlySet<number>
) => {
  const cache = new Map<bigint, boolean>();
  const dataRvas = new Set(normalizeRvaList(opts.dataRvas));
  return (address: bigint): boolean => {
    const cached = cache.get(address);
    if (cached !== undefined) return cached;
    const delta = address - opts.imageBase;
    const section = sections.find(entry => delta >= BigInt(entry.rvaStart) &&
      delta < BigInt(entry.rvaStart + entry.data.length));
    if (!section) {
      cache.set(address, false);
      return false;
    }
    const offset = Number(delta) - section.rvaStart;
    // Intel SDM, instruction format: an x86 instruction occupies at most 15 bytes.
    // https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
    const decoder = new iced.Decoder(opts.is64Bit ? 64 : 32,
      section.data.subarray(offset, offset + 15), iced.DecoderOptions.None);
    decoder.ip = address;
    let instruction: IcedInstructionObject | undefined;
    try {
      instruction = decoder.decode();
      const reference = getDirectIatReference(iced, opts.imageBase, instruction);
      const crossesData = Array.from({ length: instruction.length },
        (_value, index) => Number(delta) + index).some(rva => dataRvas.has(rva));
      const noReturn = !crossesData && reference?.kind === "jump" && slots.has(reference.slotRva);
      cache.set(address, noReturn);
      return noReturn;
    } finally {
      instruction?.free();
      decoder.free();
    }
  };
};

export const createPeNoReturnCallPredicate = (
  iced: IcedX86Module, opts: AnalyzePeInstructionSetOptions, sections: PeDisassemblySample[]
): ((instruction: IcedInstructionObject) => boolean) => {
  const slots = collectNoReturnSlots(opts);
  const isNoReturnThunk = createThunkResolver(iced, opts, sections, slots);
  return instruction => {
    if (!slots.size) return false;
    const reference = getDirectIatReference(iced, opts.imageBase, instruction);
    if (reference?.kind === "call") return slots.has(reference.slotRva);
    if (instruction.flowControl !== iced.FlowControl["Call"]) return false;
    const target = getNearBranchTarget(instruction, iced.OpKind);
    return target != null && isNoReturnThunk(target);
  };
};
