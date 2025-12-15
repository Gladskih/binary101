"use strict";

type IcedInstruction = {
  code: number;
  length: number;
  ip: bigint;
  nextIP: bigint;
  readonly flowControl: number;
  readonly nearBranchTarget: bigint;
  op0Kind: number;
  cpuidFeatures(): Int32Array;
  free(): void;
};

type IcedDecoder = {
  ip: bigint;
  canDecode: boolean;
  position: number;
  decodeOut(instruction: IcedInstruction): void;
  free(): void;
};

type IcedX86Module = {
  Code: Record<string, number> & Record<number, string | undefined>;
  Decoder: new (bitness: number, data: Uint8Array, options: number) => IcedDecoder;
  DecoderOptions: { None: number };
  FlowControl: Record<string, number> & Record<number, string | undefined>;
  OpKind: Record<string, number> & Record<number, string | undefined>;
  Instruction: new () => IcedInstruction;
};

type DisassemblySection = {
  rvaStart: number;
  data: Uint8Array;
};

type DisassemblyYieldSnapshot = {
  bytesDecoded: number;
  instructionCount: number;
  invalidInstructionCount: number;
};

const MAX_RVA = 0xffff_ffff;
const MAX_DECODE_STOP_ISSUES = 200;

const toRva = (ip: bigint, imageBase: bigint): number | null => {
  if (ip < imageBase) return null;
  const delta = ip - imageBase;
  if (delta > BigInt(MAX_RVA)) return null;
  const value = Number(delta);
  if (!Number.isSafeInteger(value) || value < 0) return null;
  return value >>> 0;
};

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

/**
 * Control-flow guided decoder used for instruction-set feature sampling.
 *
 * Key idea: avoid linear "decode everything" to reduce false positives from data regions.
 *
 * Traversal rules (to keep this maintainable, these are the semantics we rely on):
 * - Decode sequentially inside a single section until:
 *   - `RET` / `JMP [reg|mem]` / other dynamic control-flow => stop (target is unknown).
 *   - Invalid instruction => stop (likely not code bytes).
 *   - Unconditional near jump => enqueue jump target and stop current linear run.
 *   - End of section => stop (we do not cross section boundaries).
 * - Conditional near jump => enqueue branch target and continue decoding fallthrough.
 * - Near `CALL` => enqueue call target and continue decoding fallthrough.
 *   We do not try to "follow RET back to the caller": the return address is taken from the stack
 *   and is not statically knowable. Continuing after `CALL` is enough to cover the common case
 *   (return to next instruction).
 */
export async function disassembleControlFlowForInstructionSets(opts: {
  iced: IcedX86Module;
  bitness: 32 | 64;
  imageBase: bigint;
  sections: DisassemblySection[];
  entrypoints: number[];
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

  const getDecoderForRva = (rva: number): (typeof decoders)[number] | null => {
    for (const entry of decoders) {
      const start = entry.rvaStart;
      const end = start + entry.data.length;
      if (rva >= start && rva < end) return entry;
    }
    return null;
  };

  const visited = new Set<number>();
  const queued = new Set<number>();
  const queue = [...opts.entrypoints].reverse();
  for (const rva of queue) {
    queued.add(rva >>> 0);
  }

  const addWork = (rva: number | null): void => {
    if (rva == null) return;
    const normalized = rva >>> 0;
    if (visited.has(normalized) || queued.has(normalized)) return;
    queue.push(normalized);
    queued.add(normalized);
  };

  let bytesDecoded = 0;
  let instructionCount = 0;
  let invalidInstructionCount = 0;

  const instr = new opts.iced.Instruction();
  try {
    while (queue.length > 0) {
      if (opts.signal?.aborted) break;

      const startRva = queue.pop();
      if (startRva == null) break;
      queued.delete(startRva);

      const decoderEntry = getDecoderForRva(startRva);
      if (!decoderEntry) continue;

      const offset = startRva - decoderEntry.rvaStart;
      if (offset < 0 || offset >= decoderEntry.data.length) continue;

      const decoder = decoderEntry.decoder;
      decoder.position = offset;
      decoder.ip = BigInt.asUintN(64, opts.imageBase + BigInt(startRva));

      while (decoder.canDecode) {
        if (opts.signal?.aborted) return { bytesDecoded, instructionCount, invalidInstructionCount };

        decoder.decodeOut(instr);
        instructionCount++;

        const instrRva = toRva(instr.ip, opts.imageBase);
        if (instrRva == null) break;
        if (visited.has(instrRva)) break;
        visited.add(instrRva);

        const len = instr.length;
        if (len <= 0) {
          invalidInstructionCount++;
          recordDecodeStopIssue("Stopping at a zero-length instruction decode.");
          break;
        }
        bytesDecoded = Math.min(bytesSampled, bytesDecoded + len);

        const isInvalidDecode = instr.code === opts.iced.Code["INVALID"];
        const isUd2Trap = instr.code === opts.iced.Code["Ud2"];
        const isHardException = instr.flowControl === opts.iced.FlowControl["Exception"] && !isUd2Trap;
        if (isInvalidDecode || isHardException) {
          invalidInstructionCount++;
          recordDecodeStopIssue(`Stopping at an invalid instruction at RVA 0x${instrRva.toString(16)}.`);
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
            addWork(toRva(instr.nearBranchTarget, opts.imageBase));
          }
          break;
        }

        if (
          opts.iced.FlowControl["ConditionalBranch"] === instr.flowControl ||
          opts.iced.FlowControl["Call"] === instr.flowControl ||
          opts.iced.FlowControl["XbeginXabortXend"] === instr.flowControl
        ) {
          if (isNearBranch(instr.op0Kind, opts.iced.OpKind)) {
            addWork(toRva(instr.nearBranchTarget, opts.imageBase));
          }
        } else if (
          opts.iced.FlowControl["IndirectBranch"] === instr.flowControl ||
          opts.iced.FlowControl["Return"] === instr.flowControl ||
          opts.iced.FlowControl["Interrupt"] === instr.flowControl
        ) {
          break;
        }

        const nextRva = toRva(instr.nextIP, opts.imageBase);
        if (nextRva == null) break;

        const nextDecoderEntry = getDecoderForRva(nextRva);
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
