"use strict";
import type { PeSection } from "./types.js";
import { KNOWN_CPUID_FEATURES, describeCpuidFeature, formatCpuidLabel } from "./cpuid-features.js";
import type { AnalyzePeInstructionSetOptions, PeInstructionSetProgress, PeInstructionSetReport } from "./disassembly-model.js";
import { disassembleControlFlowForInstructionSets } from "./disassembly-control-flow.js";
import { isIcedX86Module } from "./disassembly-iced.js";
const IMAGE_FILE_MACHINE_I386 = 0x014c;
const IMAGE_FILE_MACHINE_AMD64 = 0x8664;
const IMAGE_SCN_CNT_CODE = 0x00000020;
const IMAGE_SCN_MEM_EXECUTE = 0x20000000;
const isExecutableSection = (section: PeSection): boolean =>
  (section.characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE)) !== 0;
const isMemoryExecutableSection = (section: PeSection): boolean =>
  (section.characteristics & IMAGE_SCN_MEM_EXECUTE) !== 0;
const findSectionContainingRva = (sections: PeSection[], rva: number): PeSection | null => {
  for (const section of sections) {
    const start = section.virtualAddress >>> 0;
    const size = Math.max(section.virtualSize >>> 0, section.sizeOfRawData >>> 0);
    const end = start + size;
    if (rva >= start && rva < end) return section;
  }
  return null;
};
const findBestCodeSection = (sections: PeSection[]): PeSection | null => {
  const byName = sections.find(section => section.name.toLowerCase() === ".text");
  if (byName) return byName;
  return sections.find(isExecutableSection) || sections[0] || null;
};
const uniqueU32s = (values: number[]): number[] => {
  const seen = new Set<number>();
  const out: number[] = [];
  for (const value of values) {
    const normalized = value >>> 0;
    if (seen.has(normalized)) continue;
    seen.add(normalized);
    out.push(normalized);
  }
  return out;
};
const reportProgress = (opts: AnalyzePeInstructionSetOptions, progress: PeInstructionSetProgress): void => {
  if (!opts.onProgress) return;
  try {
    opts.onProgress(progress);
  } catch {
    // Progress callbacks are UI-facing; analysis should continue even if a consumer throws.
  }
};
const yieldToEventLoop = async (): Promise<void> => new Promise<void>(resolve => setTimeout(resolve, 0));
export async function analyzePeInstructionSets(
  file: File,
  opts: AnalyzePeInstructionSetOptions
): Promise<PeInstructionSetReport> {
  const issues: string[] = [];
  const coffMachine = opts.coffMachine >>> 0;
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
  if (!supported) {
    issues.push(`Disassembly is only supported for x86/x86-64 (Machine ${coffMachine.toString(16)}).`);
    return emptyReport(0);
  }
  if (coffMachine === IMAGE_FILE_MACHINE_AMD64 && bitness !== 64) {
    issues.push("Machine is AMD64 but optional header reports 32-bit mode.");
  } else if (coffMachine === IMAGE_FILE_MACHINE_I386 && bitness !== 32) {
    issues.push("Machine is I386 but optional header reports 64-bit mode.");
  }
  const requestedExportRvas = uniqueU32s(
    (Array.isArray(opts.exportRvas) ? opts.exportRvas : []).filter(rva => Number.isSafeInteger(rva) && rva > 0)
  );
  const requestedUnwindBeginRvas = uniqueU32s(
    (Array.isArray(opts.unwindBeginRvas) ? opts.unwindBeginRvas : []).filter(
      rva => Number.isSafeInteger(rva) && rva > 0
    )
  );
  const requestedTlsCallbackRvas = uniqueU32s(
    (Array.isArray(opts.tlsCallbackRvas) ? opts.tlsCallbackRvas : []).filter(
      rva => Number.isSafeInteger(rva) && rva > 0
    )
  );
  const requestedEntrypointRva = Number.isSafeInteger(opts.entrypointRva) && opts.entrypointRva > 0
    ? (opts.entrypointRva >>> 0)
    : 0;

  const resolvedEntrypoints: number[] = [];
  const resolvedEntrypointsSet = new Set<number>();
  const addEntrypoint = (source: "Entry point" | "Export" | "Unwind" | "TLS callback", rva: number): void => {
    const normalized = rva >>> 0;
    if (resolvedEntrypointsSet.has(normalized)) return;

    const off = opts.rvaToOff(normalized);
    if (off == null) {
      issues.push(`${source} RVA 0x${normalized.toString(16)} could not be mapped to a file offset.`);
      return;
    }

    const containing = findSectionContainingRva(opts.sections, normalized);
    if (!containing) {
      issues.push(`${source} RVA 0x${normalized.toString(16)} is not within any section.`);
      return;
    }

    if (!isMemoryExecutableSection(containing)) {
      issues.push(
        `${source} RVA 0x${normalized.toString(16)} points into a non-executable section (${containing.name}; missing IMAGE_SCN_MEM_EXECUTE).`
      );
      return;
    }

    resolvedEntrypointsSet.add(normalized);
    resolvedEntrypoints.push(normalized);
  };

  if (requestedEntrypointRva) {
    addEntrypoint("Entry point", requestedEntrypointRva);
  }
  for (const rva of requestedExportRvas) {
    addEntrypoint("Export", rva);
  }
  for (const rva of requestedUnwindBeginRvas) {
    addEntrypoint("Unwind", rva);
  }
  for (const rva of requestedTlsCallbackRvas) {
    addEntrypoint("TLS callback", rva);
  }
  if (resolvedEntrypoints.length === 0) {
    const fallback = findBestCodeSection(opts.sections);
    if (!fallback) {
      issues.push("No section headers available to locate code bytes.");
      return emptyReport(0);
    }
    resolvedEntrypoints.push(fallback.virtualAddress >>> 0);
    issues.push(`Falling back to section ${fallback.name || "(unnamed)"} for disassembly sample.`);
  }
  if (opts.signal?.aborted) {
    issues.push("Disassembly cancelled.");
    return emptyReport(0);
  }
  const imageBase = Number.isSafeInteger(opts.imageBase) && opts.imageBase >= 0 ? BigInt(opts.imageBase) : 0n;
  if (!Number.isSafeInteger(opts.imageBase)) {
    issues.push("ImageBase is not a safe integer; instruction pointers may be approximate.");
  }
  const entrypointSections = resolvedEntrypoints
    .map(rva => findSectionContainingRva(opts.sections, rva))
    .filter((section): section is PeSection => section != null);
  const sectionsToSample = uniqueU32s([
    ...opts.sections.filter(isExecutableSection).map(section => section.virtualAddress >>> 0),
    ...entrypointSections.map(section => section.virtualAddress >>> 0)
  ])
    .map(rva => findSectionContainingRva(opts.sections, rva))
    .filter((section): section is PeSection => section != null);
  if (sectionsToSample.length === 0) {
    issues.push("No section headers available to locate code bytes.");
    return emptyReport(0);
  }
  const loadSectionBytes = async (section: PeSection): Promise<Uint8Array> => {
    const start = section.pointerToRawData >>> 0;
    const size = section.sizeOfRawData >>> 0;
    if (!size) return new Uint8Array();
    const end = Math.min(file.size, start + size);
    if (start >= file.size || end <= start) return new Uint8Array();
    return new Uint8Array(await file.slice(start, end).arrayBuffer());
  };
  const sampledSections = (
    await Promise.all(
      sectionsToSample.map(async section => ({
        rvaStart: section.virtualAddress >>> 0,
        data: await loadSectionBytes(section)
      }))
    )
  ).filter(entry => entry.data.length > 0);
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
    iced = await import("iced-x86");
  } catch (err) {
    issues.push(`Failed to load iced-x86 disassembler (${String(err)})`);
    return emptyReport(bytesSampled);
  }
  if (!isIcedX86Module(iced)) {
    issues.push("Failed to load iced-x86 disassembler (unexpected module shape).");
    return emptyReport(bytesSampled);
  }
  const featureCounts = new Map<number, number>();
  const knownFeatures = KNOWN_CPUID_FEATURES
    .map(id => ({ id, value: iced.CpuidFeature[id] }))
    .filter((entry): entry is { id: string; value: number } => typeof entry.value === "number");
  const getKnownFeatureCounts = (): Record<string, number> => {
    const out: Record<string, number> = {};
    for (const { id, value } of knownFeatures) {
      const count = featureCounts.get(value);
      if (count) out[id] = count;
    }
    return out;
  };
  let bytesDecoded = 0;
  let instructionCount = 0;
  let invalidInstructionCount = 0;
  reportProgress(opts, {
    stage: "decoding",
    bytesSampled,
    bytesDecoded,
    instructionCount,
    invalidInstructionCount,
    knownFeatureCounts: getKnownFeatureCounts()
  });
  try {
    const result = await disassembleControlFlowForInstructionSets({
      iced,
      bitness,
      imageBase,
      sections: sampledSections,
      entrypoints: resolvedEntrypoints,
      yieldEveryInstructions,
      featureCounts,
      issues,
      ...(opts.signal ? { signal: opts.signal } : {}),
      onYield: async snapshot => {
        bytesDecoded = snapshot.bytesDecoded;
        instructionCount = snapshot.instructionCount;
        invalidInstructionCount = snapshot.invalidInstructionCount;
        reportProgress(opts, {
          stage: "decoding",
          bytesSampled,
          bytesDecoded,
          instructionCount,
          invalidInstructionCount,
          knownFeatureCounts: getKnownFeatureCounts()
        });
        await yieldToEventLoop();
      }
    });
    bytesDecoded = result.bytesDecoded;
    instructionCount = result.instructionCount;
    invalidInstructionCount = result.invalidInstructionCount;
  } catch (err) {
    issues.push(`Disassembly failed (${String(err)})`);
  }
  const instructionSets = [...featureCounts.entries()]
    .map(([feature, count]) => {
      const id = iced.CpuidFeature[feature] ?? `#${feature}`;
      return {
        id,
        label: formatCpuidLabel(id),
        description: describeCpuidFeature(id),
        instructionCount: count
      };
    })
    .sort((a, b) => b.instructionCount - a.instructionCount || a.id.localeCompare(b.id));
  reportProgress(opts, {
    stage: "done",
    bytesSampled,
    bytesDecoded,
    instructionCount,
    invalidInstructionCount,
    knownFeatureCounts: getKnownFeatureCounts()
  });
  return {
    bitness,
    bytesSampled,
    bytesDecoded,
    instructionCount,
    invalidInstructionCount,
    instructionSets,
    issues
  };
}
