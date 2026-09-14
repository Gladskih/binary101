import type { Disassembler } from "llvm-aarch64-disasm";
import { createAarch64VisitedTracker } from "./visited-addresses.js";
import { createAarch64CodeWindow } from "./code-window.js";
import { createAarch64SampleDecoder, type Aarch64InstructionSample } from "./sample-decoder.js";
import type {
  AnalyzeElfInstructionSetOptions, ElfInstructionSetReport, ElfInstructionSetProgress,
  ElfInstructionSetUsage
} from "../elf/disassembly-types.js";
import { recordAarch64Requirements } from "./instruction-set-usage.js";

export const notifyAarch64Progress = (
  opts: Pick<AnalyzeElfInstructionSetOptions, "signal" | "onProgress" | "yieldEveryInstructions">,
  report: ElfInstructionSetReport,
  stage: ElfInstructionSetProgress["stage"]
): void => {
  try {
    opts.onProgress?.({
      aarch64InstructionSets: report.instructionSets.map(set => ({ ...set })),
      stage, bytesSampled: report.bytesSampled, bytesDecoded: report.bytesDecoded,
      instructionCount: report.instructionCount, invalidInstructionCount: report.invalidInstructionCount
    });
  } catch {
    // A consumer callback must not interrupt parsing.
  }
};

const nextAddresses = (instruction: Aarch64InstructionSample): bigint[] => {
  if (instruction.status === "invalid") return [];
  const targets = instruction.target === undefined ? [] : [instruction.target];
  switch (instruction.controlFlow) {
    case "return": case "indirect-branch": return [];
    case "unconditional-branch": return targets;
    default: return [...targets, BigInt.asUintN(64, instruction.address + 4n)];
  }
};

const recordInstruction = (
  instruction: Aarch64InstructionSample,
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
  opts: Pick<AnalyzeElfInstructionSetOptions, "signal" | "onProgress" | "yieldEveryInstructions">,
  report: ElfInstructionSetReport
): Promise<void> => {
  const pending = [...entrypoints];
  const visit = createAarch64VisitedTracker();
  const readWindow = createAarch64CodeWindow(readCode);
  const decode = createAarch64SampleDecoder(decoder);
  let visitedCount = 0;
  let lastYield = performance.now();
  const usage = new Map<string, ElfInstructionSetUsage>();
  const interval = Number.isSafeInteger(opts.yieldEveryInstructions) && opts.yieldEveryInstructions! > 0
    ? opts.yieldEveryInstructions! : 1024;
  notifyAarch64Progress(opts, report, "decoding");
  try {
    while (!opts.signal?.aborted) {
      const address = nextUnvisitedAddress(pending, visit, report.issues);
      if (address === undefined) break;
      const bytes = readWindow(address);
      recordBytes(decode, bytes instanceof Uint8Array ? bytes : await bytes,
        address, pending, report, usage);
      if (++visitedCount % interval === 0) {
        report.instructionSets = [...usage.values()];
        notifyAarch64Progress(opts, report, "decoding");
        // A frame-sized work budget avoids browser timer clamping on every 1024 words.
        if (performance.now() - lastYield >= 16) {
          await new Promise<void>(resolve => setTimeout(resolve, 0));
          lastYield = performance.now();
        }
      }
    }
  } finally {
    report.instructionSets = [...usage.values()];
    if (opts.signal?.aborted) report.issues.push("Disassembly cancelled.");
  }
};

const nextUnvisitedAddress = (
  pending: bigint[], visit: ReturnType<typeof createAarch64VisitedTracker>, issues: string[]
): bigint | undefined => {
  while (pending.length) {
    const address = pending.pop()!;
    const status = visit(address);
    if (status === "new") return address;
    if (status === "limit") {
      issues.push("AArch64 sampling stopped at the visited-address memory budget (32 MiB).");
      return undefined;
    }
    if (status === "invalid") issues.push(`Skipped invalid or unaligned AArch64 code address ${address}.`);
  }
  return undefined;
};

const recordBytes = (
  decode: ReturnType<typeof createAarch64SampleDecoder>,
  bytes: Uint8Array,
  address: bigint,
  pending: bigint[],
  report: ElfInstructionSetReport,
  usage: Map<string, ElfInstructionSetUsage>
): void => {
  if (!bytes.length) return;
  if (bytes.length < 4) report.issues.push(`Truncated AArch64 instruction at 0x${address.toString(16)}.`);
  const instruction = decode(bytes, address);
  recordInstruction(instruction, report, usage);
  pending.push(...nextAddresses(instruction));
};
