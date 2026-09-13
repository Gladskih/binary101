import type { DecodeResult, Disassembler } from "llvm-aarch64-disasm";
import type {
  AnalyzeElfInstructionSetOptions, ElfInstructionSetReport, ElfInstructionSetProgress,
  ElfInstructionSetUsage
} from "../elf/disassembly-types.js";
import { recordAarch64Requirements } from "./instruction-set-usage.js";

export const notifyAarch64Progress = (
  opts: AnalyzeElfInstructionSetOptions,
  report: ElfInstructionSetReport,
  stage: ElfInstructionSetProgress["stage"]
): void => {
  try {
    opts.onProgress?.({
      stage, bytesSampled: report.bytesSampled, bytesDecoded: report.bytesDecoded,
      instructionCount: report.instructionCount, invalidInstructionCount: report.invalidInstructionCount
    });
  } catch {
    // A consumer callback must not interrupt parsing.
  }
};

const nextAddresses = (instruction: DecodeResult): bigint[] => {
  if (instruction.status === "invalid") return [];
  const targets = instruction.target === undefined ? [] : [instruction.target];
  switch (instruction.controlFlow) {
    case "return": case "indirect-branch": return [];
    case "unconditional-branch": return targets;
    default: return [...targets, BigInt.asUintN(64, instruction.address + 4n)];
  }
};

const recordInstruction = (
  instruction: DecodeResult,
  report: ElfInstructionSetReport,
  usage: Map<string, ElfInstructionSetUsage>
): void => {
  if (instruction.status === "invalid") {
    report.invalidInstructionCount += 1;
    return;
  }
  report.instructionCount += 1;
  report.bytesDecoded += instruction.length;
  if (instruction.status === "soft-fail" && !report.issues.includes("LLVM reported soft-fail instructions.")) {
    report.issues.push("LLVM reported soft-fail instructions.");
  }
  recordAarch64Requirements(instruction.features, usage);
};

export const walkAarch64ControlFlow = async (
  decoder: Disassembler,
  readCode: (address: bigint) => Promise<Uint8Array>,
  entrypoints: bigint[],
  opts: AnalyzeElfInstructionSetOptions,
  report: ElfInstructionSetReport
): Promise<void> => {
  const pending = [...entrypoints];
  const visited = new Set<bigint>();
  const usage = new Map<string, ElfInstructionSetUsage>();
  const interval = Number.isSafeInteger(opts.yieldEveryInstructions) && opts.yieldEveryInstructions! > 0
    ? opts.yieldEveryInstructions! : 1024;
  notifyAarch64Progress(opts, report, "decoding");
  try {
    while (pending.length && !opts.signal?.aborted) {
      const address = pending.pop()!;
      if (visited.has(address)) continue;
      visited.add(address);
      await decodeAddress(decoder, readCode, address, pending, report, usage);
      if (visited.size % interval === 0) {
        notifyAarch64Progress(opts, report, "decoding");
        await new Promise<void>(resolve => setTimeout(resolve, 0));
      }
    }
  } finally {
    report.instructionSets = [...usage.values()];
    if (opts.signal?.aborted) report.issues.push("Disassembly cancelled.");
  }
};

const decodeAddress = async (
  decoder: Disassembler,
  readCode: (address: bigint) => Promise<Uint8Array>,
  address: bigint,
  pending: bigint[],
  report: ElfInstructionSetReport,
  usage: Map<string, ElfInstructionSetUsage>
): Promise<void> => {
  // A64 instructions are four-byte aligned (AAELF64, Mapping symbols).
  if (address < 0n || address > 0xffffffffffffffffn || address % 4n !== 0n) {
    report.issues.push(`Skipped invalid or unaligned AArch64 code address ${address}.`);
    return;
  }
  const bytes = await readCode(address);
  if (!bytes.length) return;
  if (bytes.length < 4) report.issues.push(`Truncated AArch64 instruction at 0x${address.toString(16)}.`);
  const instruction = decoder.decode(bytes, { address })[0];
  if (!instruction) throw new Error("AArch64 decoder returned no instruction.");
  recordInstruction(instruction, report, usage);
  pending.push(...nextAddresses(instruction));
};
