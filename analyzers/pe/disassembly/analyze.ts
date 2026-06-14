"use strict";
import type { FileRangeReader } from "../../file-range-reader.js";
import type { AnalyzePeInstructionSetOptions, PeInstructionSetProgress, PeInstructionSetReport } from "./types.js";
import { disassembleControlFlowForInstructionSets } from "../../x86/disassembly-control-flow.js";
import { isIcedX86Module, type IcedX86Module } from "../../x86/disassembly-iced.js";
import { loadIcedX86 } from "#iced-x86-loader";
import { IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_I386, getCanonicalPeMachine } from "../machine.js";
import { createX86InstructionSetUsageTracker } from "../../x86/instruction-set-usage.js";
import {
  collectPeDisassemblySamples,
  type PeDisassemblySample,
  resolvePeDisassemblyEntrypoints
} from "./sampling.js";

type PeInstructionSetDecodeRun = {
  iced: IcedX86Module;
  bitness: 32 | 64;
  imageBase: bigint;
  sampledSections: PeDisassemblySample[];
  resolvedEntrypoints: number[];
  yieldEveryInstructions: number;
  bytesSampled: number;
  issues: string[];
  opts: AnalyzePeInstructionSetOptions;
};

type PeInstructionSetDecodeResult = {
  bytesDecoded: number;
  instructionCount: number;
  invalidInstructionCount: number;
  instructionSets: PeInstructionSetReport["instructionSets"];
};

const reportProgress = (opts: AnalyzePeInstructionSetOptions, progress: PeInstructionSetProgress): void => {
  if (!opts.onProgress) return;
  try { opts.onProgress(progress); } catch { /* UI callbacks must not abort analysis. */ }
};
const yieldToEventLoop = async (): Promise<void> => new Promise<void>(resolve => setTimeout(resolve, 0));
export async function analyzePeInstructionSets(
  reader: FileRangeReader,
  opts: AnalyzePeInstructionSetOptions
): Promise<PeInstructionSetReport> {
  const issues: string[] = [];
  const coffMachine = getCanonicalPeMachine(opts.coffMachine);
  const supported = coffMachine === IMAGE_FILE_MACHINE_I386 || coffMachine === IMAGE_FILE_MACHINE_AMD64;
  const bitness: 32 | 64 = opts.is64Bit ? 64 : 32;
  const yieldEveryInstructions =
    typeof opts.yieldEveryInstructions === "number" &&
    Number.isSafeInteger(opts.yieldEveryInstructions) &&
    opts.yieldEveryInstructions > 0
      ? opts.yieldEveryInstructions
      : 0;
  const emptyReport = (bytesSampled: number): PeInstructionSetReport => ({
    bitness,
    bytesSampled,
    bytesDecoded: 0,
    instructionCount: 0,
    invalidInstructionCount: 0,
    instructionSets: [],
    issues
  });
  if (!supported) return (issues.push(`Disassembly is only supported for x86/x86-64 (Machine ${coffMachine.toString(16)}).`), emptyReport(0));
  if (coffMachine === IMAGE_FILE_MACHINE_AMD64 && bitness !== 64) {
    issues.push("Machine is AMD64 but optional header reports 32-bit mode.");
  } else if (coffMachine === IMAGE_FILE_MACHINE_I386 && bitness !== 32) {
    issues.push("Machine is I386 but optional header reports 64-bit mode.");
  }
  const resolvedEntrypoints = resolvePeDisassemblyEntrypoints(opts, issues);
  if (!resolvedEntrypoints.length) return emptyReport(0);
  if (opts.signal?.aborted) {
    issues.push("Disassembly cancelled.");
    return emptyReport(0);
  }
  const imageBase = opts.imageBase >= 0n ? opts.imageBase : 0n;
  if (opts.imageBase < 0n) {
    issues.push("ImageBase is negative; instruction pointers may be approximate.");
  }
  const sampledSections = await collectPeDisassemblySamples(reader, opts, resolvedEntrypoints);
  if (sampledSections.length === 0 && resolvedEntrypoints.every(rva => opts.rvaToOff(rva) == null)) {
    issues.push("No section headers available to locate code bytes.");
    return emptyReport(0);
  }
  const bytesSampled = sampledSections.reduce((sum, entry) => sum + entry.data.length, 0);
  if (bytesSampled === 0) {
    issues.push("No bytes available in selected section(s) for disassembly.");
    return emptyReport(0);
  }
  reportProgress(opts, {
    stage: "loading",
    bytesSampled,
    bytesDecoded: 0,
    instructionCount: 0,
    invalidInstructionCount: 0
  });
  if (opts.signal?.aborted) {
    issues.push("Disassembly cancelled.");
    return emptyReport(bytesSampled);
  }
  let iced: unknown;
  try {
    iced = await loadIcedX86();
  } catch (err) {
    issues.push(`Failed to load iced-x86 disassembler (${String(err)})`);
    return emptyReport(bytesSampled);
  }
  if (!isIcedX86Module(iced)) {
    issues.push("Failed to load iced-x86 disassembler (unexpected module shape).");
    return emptyReport(bytesSampled);
  }
  const decoded = await decodePeInstructionSetUsage({
    iced,
    bitness,
    imageBase,
    sampledSections,
    resolvedEntrypoints,
    yieldEveryInstructions,
    bytesSampled,
    issues,
    opts
  });
  return {
    bitness,
    bytesSampled,
    bytesDecoded: decoded.bytesDecoded,
    instructionCount: decoded.instructionCount,
    invalidInstructionCount: decoded.invalidInstructionCount,
    instructionSets: decoded.instructionSets,
    issues
  };
}

const decodePeInstructionSetUsage = async (
  run: PeInstructionSetDecodeRun
): Promise<PeInstructionSetDecodeResult> => {
  const { iced, bitness, imageBase, sampledSections, resolvedEntrypoints } = run;
  const instructionSetUsage = createX86InstructionSetUsageTracker(iced.CpuidFeature);
  let bytesDecoded = 0; let instructionCount = 0; let invalidInstructionCount = 0;
  reportProgress(run.opts, {
    stage: "decoding",
    bytesSampled: run.bytesSampled,
    bytesDecoded,
    instructionCount,
    invalidInstructionCount,
    knownFeatureCounts: instructionSetUsage.knownFeatureCounts()
  });
  try {
    const result = await disassembleControlFlowForInstructionSets({
      iced,
      bitness,
      imageBase,
      sections: sampledSections,
      entrypoints: resolvedEntrypoints,
      yieldEveryInstructions: run.yieldEveryInstructions,
      featureCounts: instructionSetUsage.featureCounts,
      issues: run.issues,
      ...(run.opts.signal ? { signal: run.opts.signal } : {}),
      onYield: async snapshot => {
        bytesDecoded = snapshot.bytesDecoded;
        instructionCount = snapshot.instructionCount;
        invalidInstructionCount = snapshot.invalidInstructionCount;
        reportProgress(run.opts, {
          stage: "decoding",
          bytesSampled: run.bytesSampled,
          bytesDecoded,
          instructionCount,
          invalidInstructionCount,
          knownFeatureCounts: instructionSetUsage.knownFeatureCounts()
        });
        await yieldToEventLoop();
      }
    });
    bytesDecoded = result.bytesDecoded;
    instructionCount = result.instructionCount;
    invalidInstructionCount = result.invalidInstructionCount;
  } catch (err) {
    run.issues.push(`Disassembly failed (${String(err)})`);
  }
  reportProgress(run.opts, {
    stage: "done",
    bytesSampled: run.bytesSampled,
    bytesDecoded,
    instructionCount,
    invalidInstructionCount,
    knownFeatureCounts: instructionSetUsage.knownFeatureCounts()
  });
  return {
    bytesDecoded,
    instructionCount,
    invalidInstructionCount,
    instructionSets: instructionSetUsage.instructionSets(),
  };
};
