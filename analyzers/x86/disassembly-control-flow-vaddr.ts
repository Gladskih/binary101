"use strict";

import type { IcedX86Module } from "./disassembly-iced.js";

type DisassemblySectionVaddr = {
  vaddrStart: bigint;
  data: Uint8Array<ArrayBufferLike>;
};

type DisassemblyYieldSnapshot = {
  bytesDecoded: number;
  instructionCount: number;
  invalidInstructionCount: number;
};

const MAX_DECODE_STOP_ISSUES = 200;

const isNearBranch = (opKind: number, OpKind: IcedX86Module["OpKind"]): boolean =>
  opKind === OpKind["NearBranch16"] || opKind === OpKind["NearBranch32"] || opKind === OpKind["NearBranch64"];

const safeFree = (resource: { free(): void } | null | undefined): void => {
  if (!resource) return;
  try {
    resource.free();
  } catch {
    // Best-effort cleanup: iced-x86 objects own WASM allocations and `free()` may throw if the module
    // is partially initialized/aborted or if the object has already been released.
    // Cleanup errors should never override real analysis results.
  }
};

const tryGetOffsetInSection = (vaddr: bigint, section: DisassemblySectionVaddr): number | null => {
  const end = section.vaddrStart + BigInt(section.data.length);
  if (vaddr < section.vaddrStart || vaddr >= end) return null;
  const delta = vaddr - section.vaddrStart;
  const offset = Number(delta);
  if (!Number.isSafeInteger(offset) || offset < 0 || offset >= section.data.length) return null;
  return offset;
};

/**
 * Control-flow guided decoder used for instruction-set feature sampling (ELF-style vaddr mapping).
 *
 * This version does not rely on a 32-bit RVA space and can operate on full 64-bit virtual addresses
 * as long as the decoded addresses still map back into one of the sampled byte ranges.
 */
export async function disassembleControlFlowForInstructionSetsVaddr(opts: {
  iced: IcedX86Module;
  bitness: 32 | 64;
  sections: DisassemblySectionVaddr[];
  entrypoints: bigint[];
  yieldEveryInstructions: number;
  featureCounts: Map<number, number>;
  issues: string[];
  signal?: AbortSignal;
  onYield?: (snapshot: DisassemblyYieldSnapshot) => Promise<void>;
}): Promise<DisassemblyYieldSnapshot> {
  const bytesSampled = opts.sections.reduce((sum, entry) => sum + entry.data.length, 0);
  const decoders = opts.sections.map(entry => ({
    ...entry,
    decoder: new opts.iced.Decoder(opts.bitness, entry.data, opts.iced.DecoderOptions.None)
  }));

  let decodeStopIssuesLogged = 0;
  let decodeStopIssuesSuppressed = 0;
  const recordDecodeStopIssue = (message: string): void => {
    if (decodeStopIssuesLogged < MAX_DECODE_STOP_ISSUES) {
      opts.issues.push(message);
      decodeStopIssuesLogged += 1;
    } else {
      decodeStopIssuesSuppressed += 1;
    }
  };

  const getDecoderForVaddr = (vaddr: bigint): (typeof decoders)[number] | null => {
    for (const entry of decoders) {
      if (tryGetOffsetInSection(vaddr, entry) != null) return entry;
    }
    return null;
  };

  const visited = new Set<bigint>();
  const queued = new Set<bigint>();
  const queue = [...opts.entrypoints].reverse();
  for (const vaddr of queue) {
    queued.add(vaddr);
  }

  const addWork = (vaddr: bigint | null): void => {
    if (vaddr == null) return;
    if (visited.has(vaddr) || queued.has(vaddr)) return;
    if (!getDecoderForVaddr(vaddr)) return;
    queue.push(vaddr);
    queued.add(vaddr);
  };

  let bytesDecoded = 0;
  let instructionCount = 0;
  let invalidInstructionCount = 0;

  const instr = new opts.iced.Instruction();
  try {
    while (queue.length > 0) {
      if (opts.signal?.aborted) break;

      const startVaddr = queue.pop();
      if (startVaddr == null) break;
      queued.delete(startVaddr);

      const decoderEntry = getDecoderForVaddr(startVaddr);
      if (!decoderEntry) continue;

      const offset = tryGetOffsetInSection(startVaddr, decoderEntry);
      if (offset == null) continue;

      const decoder = decoderEntry.decoder;
      decoder.position = offset;
      decoder.ip = BigInt.asUintN(64, startVaddr);

      while (decoder.canDecode) {
        if (opts.signal?.aborted) return { bytesDecoded, instructionCount, invalidInstructionCount };

        decoder.decodeOut(instr);
        instructionCount += 1;

        const instrVaddr = BigInt.asUintN(64, instr.ip);
        if (visited.has(instrVaddr)) break;
        visited.add(instrVaddr);

        const len = instr.length;
        if (len <= 0) {
          invalidInstructionCount += 1;
          recordDecodeStopIssue("Stopping at a zero-length instruction decode.");
          break;
        }
        bytesDecoded = Math.min(bytesSampled, bytesDecoded + len);

        const isInvalidDecode = instr.code === opts.iced.Code["INVALID"];
        const isUd2Trap = instr.code === opts.iced.Code["Ud2"];
        const isHardException = instr.flowControl === opts.iced.FlowControl["Exception"] && !isUd2Trap;
        if (isInvalidDecode || isHardException) {
          invalidInstructionCount += 1;
          recordDecodeStopIssue(`Stopping at an invalid instruction at address 0x${instrVaddr.toString(16)}.`);
          break;
        }

        if (!isUd2Trap) {
          const features = instr.cpuidFeatures();
          for (const feature of features) {
            opts.featureCounts.set(feature, (opts.featureCounts.get(feature) || 0) + 1);
          }
        }

        if (opts.iced.FlowControl["UnconditionalBranch"] === instr.flowControl) {
          if (isNearBranch(instr.op0Kind, opts.iced.OpKind)) {
            addWork(BigInt.asUintN(64, instr.nearBranchTarget));
          }
          break;
        }

        if (
          opts.iced.FlowControl["ConditionalBranch"] === instr.flowControl ||
          opts.iced.FlowControl["Call"] === instr.flowControl ||
          opts.iced.FlowControl["XbeginXabortXend"] === instr.flowControl
        ) {
          if (isNearBranch(instr.op0Kind, opts.iced.OpKind)) {
            addWork(BigInt.asUintN(64, instr.nearBranchTarget));
          }
        } else if (
          opts.iced.FlowControl["IndirectBranch"] === instr.flowControl ||
          opts.iced.FlowControl["Return"] === instr.flowControl ||
          opts.iced.FlowControl["Interrupt"] === instr.flowControl
        ) {
          break;
        }

        const nextVaddr = BigInt.asUintN(64, instr.nextIP);
        const nextDecoderEntry = getDecoderForVaddr(nextVaddr);
        if (!nextDecoderEntry || nextDecoderEntry !== decoderEntry) {
          break;
        }

        if (opts.yieldEveryInstructions && instructionCount % opts.yieldEveryInstructions === 0) {
          await opts.onYield?.({ bytesDecoded, instructionCount, invalidInstructionCount });
        }
      }
    }
    return { bytesDecoded, instructionCount, invalidInstructionCount };
  } finally {
    if (decodeStopIssuesSuppressed > 0) {
      opts.issues.push(
        `Additional ${decodeStopIssuesSuppressed} decode stop(s) omitted; showing first ${MAX_DECODE_STOP_ISSUES}.`
      );
    }
    safeFree(instr);
    for (const entry of decoders) {
      safeFree(entry.decoder);
    }
  }
}

