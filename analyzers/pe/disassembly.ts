import type { PeSection, RvaToOffset } from "./types.js";
import { describeCpuidFeature, formatCpuidLabel } from "./cpuid-features.js";

export interface PeInstructionSetUsage {
  id: string;
  label: string;
  description: string;
  instructionCount: number;
}

export interface PeInstructionSetReport {
  bitness: 32 | 64;
  bytesSampled: number;
  bytesDecoded: number;
  instructionCount: number;
  invalidInstructionCount: number;
  instructionSets: PeInstructionSetUsage[];
  issues: string[];
}

export interface AnalyzePeInstructionSetOptions {
  coffMachine: number;
  is64Bit: boolean;
  imageBase: number;
  entrypointRva: number;
  rvaToOff: RvaToOffset;
  sections: PeSection[];
  maxDecodeBytes?: number;
  maxInstructions?: number;
  yieldEveryInstructions?: number;
  signal?: AbortSignal;
  onProgress?: (progress: PeInstructionSetProgress) => void;
}

export interface PeInstructionSetProgress {
  stage: "loading" | "decoding" | "done";
  bytesSampled: number;
  bytesDecoded: number;
  instructionCount: number;
  invalidInstructionCount: number;
}

interface IcedInstruction {
  code: number;
  length: number;
  cpuidFeatures(): Int32Array;
  free(): void;
}
interface IcedDecoder {
  ip: bigint;
  canDecode: boolean;
  decode(): IcedInstruction;
  decodeOut(instruction: IcedInstruction): void;
  free(): void;
}
interface IcedX86Module {
  Code: Record<string, number> & Record<number, string | undefined>;
  CpuidFeature: Record<string, number> & Record<number, string | undefined>;
  Decoder: new (bitness: number, data: Uint8Array, options: number) => IcedDecoder;
  DecoderOptions: { None: number };
}
const IMAGE_FILE_MACHINE_I386 = 0x014c;
const IMAGE_FILE_MACHINE_AMD64 = 0x8664;
const IMAGE_SCN_CNT_CODE = 0x00000020;

const DEFAULT_MAX_DECODE_BYTES = 256 * 1024;
const DEFAULT_MAX_INSTRUCTIONS = 100_000;
const MAX_CONSECUTIVE_INVALID = 128;

const isExecutableSection = (section: PeSection): boolean => (section.characteristics & IMAGE_SCN_CNT_CODE) !== 0;

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

const reportProgress = (opts: AnalyzePeInstructionSetOptions, progress: PeInstructionSetProgress): void => {
  if (!opts.onProgress) return;
  try { opts.onProgress(progress); } catch { /* ignore */ }
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
  const maxDecodeBytes =
    typeof opts.maxDecodeBytes === "number" &&
    Number.isSafeInteger(opts.maxDecodeBytes) &&
    opts.maxDecodeBytes > 0
      ? opts.maxDecodeBytes
      : DEFAULT_MAX_DECODE_BYTES;
  const maxInstructions =
    typeof opts.maxInstructions === "number" &&
    Number.isSafeInteger(opts.maxInstructions) &&
    opts.maxInstructions > 0
      ? opts.maxInstructions
      : DEFAULT_MAX_INSTRUCTIONS;
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
    issues.push(
      `Disassembly is only supported for x86/x86-64 (Machine ${coffMachine.toString(16)}).`
    );
    return emptyReport(0);
  }

  if (coffMachine === IMAGE_FILE_MACHINE_AMD64 && bitness !== 64) {
    issues.push("Machine is AMD64 but optional header reports 32-bit mode.");
  } else if (coffMachine === IMAGE_FILE_MACHINE_I386 && bitness !== 32) {
    issues.push("Machine is I386 but optional header reports 64-bit mode.");
  }

  let startRva = opts.entrypointRva >>> 0;
  let startOffset = startRva ? opts.rvaToOff(startRva) : null;
  let section: PeSection | null = null;

  if (startOffset != null && startRva) {
    section = findSectionContainingRva(opts.sections, startRva);
  } else if (startRva) {
    issues.push(`Entrypoint RVA 0x${startRva.toString(16)} could not be mapped to a file offset.`);
  }

  if (!startRva || startOffset == null) {
    section = findBestCodeSection(opts.sections);
    if (!section) {
      issues.push("No section headers available to locate code bytes.");
      return emptyReport(0);
    }
    startRva = section.virtualAddress >>> 0;
    startOffset = section.pointerToRawData >>> 0;
    issues.push(`Falling back to section ${section.name || "(unnamed)"} for disassembly sample.`);
  }

  const sectionEnd = section
    ? Math.min(file.size, (section.pointerToRawData >>> 0) + (section.sizeOfRawData >>> 0))
    : file.size;
  const sliceEnd = Math.min(sectionEnd, startOffset + maxDecodeBytes);
  if (startOffset >= file.size || sliceEnd <= startOffset) {
    issues.push("No bytes available at selected disassembly start offset.");
    return emptyReport(0);
  }

  const data = new Uint8Array(await file.slice(startOffset, sliceEnd).arrayBuffer());
  if (data.length === 0) {
    issues.push("Disassembly sample is empty after bounds checks.");
    return emptyReport(0);
  }

  if (opts.signal?.aborted) {
    issues.push("Disassembly cancelled.");
    return emptyReport(data.length);
  }

  let iced: IcedX86Module;
  reportProgress(opts, {
    stage: "loading",
    bytesSampled: data.length,
    bytesDecoded: 0,
    instructionCount: 0,
    invalidInstructionCount: 0
  });
  try {
    iced = (await import("iced-x86")) as unknown as IcedX86Module;
  } catch (err) {
    issues.push(`Failed to load iced-x86 disassembler (${String(err)})`);
    return emptyReport(data.length);
  }
  const { Code, CpuidFeature, Decoder, DecoderOptions } = iced;

  const featureCounts = new Map<number, number>();
  let instructionCount = 0;
  let invalidInstructionCount = 0;
  let bytesDecoded = 0;
  let consecutiveInvalid = 0;

  const decoder = new Decoder(bitness, data, DecoderOptions.None);
  const imageBase = Number.isSafeInteger(opts.imageBase) && opts.imageBase >= 0 ? BigInt(opts.imageBase) : 0n;
  if (!Number.isSafeInteger(opts.imageBase)) {
    issues.push("ImageBase is not a safe integer; instruction pointers may be approximate.");
  }
  decoder.ip = BigInt.asUintN(64, imageBase + BigInt(startRva));

  let instr: IcedInstruction | null = null;
  try {
    instr = decoder.decode();
    while (true) {
      instructionCount++;
      if (opts.signal?.aborted) {
        issues.push("Disassembly cancelled.");
        break;
      }

      const len = instr.length;
      if (len <= 0) {
        invalidInstructionCount++;
        issues.push("Stopping early after a zero-length instruction decode.");
        break;
      }
      bytesDecoded = Math.min(data.length, bytesDecoded + len);

      if (instr.code === Code["INVALID"]) {
        invalidInstructionCount++;
        consecutiveInvalid++;
      } else {
        consecutiveInvalid = 0;
        const features = instr.cpuidFeatures();
        for (const feature of features) {
          featureCounts.set(feature, (featureCounts.get(feature) || 0) + 1);
        }
      }

      if (consecutiveInvalid >= MAX_CONSECUTIVE_INVALID) {
        issues.push("Stopping early after too many consecutive invalid instructions (likely not code bytes).");
        break;
      }
      if (!decoder.canDecode) break;
      if (instructionCount >= maxInstructions) {
        issues.push(`Stopping after ${maxInstructions} instructions (analysis limit).`);
        break;
      }

      if (yieldEveryInstructions && instructionCount % yieldEveryInstructions === 0) {
        reportProgress(opts, {
          stage: "decoding",
          bytesSampled: data.length,
          bytesDecoded,
          instructionCount,
          invalidInstructionCount
        });
        await yieldToEventLoop();
      }

      decoder.decodeOut(instr);
    }
  } catch (err) {
    issues.push(`Disassembly failed (${String(err)})`);
  } finally {
    try {
      instr?.free();
    } catch {
      // ignore
    }
    try {
      decoder.free();
    } catch {
      // ignore
    }
  }

  const instructionSets = [...featureCounts.entries()]
    .map(([feature, count]) => {
      const id = (CpuidFeature as Record<number, string | undefined>)[feature] || `#${feature}`;
      return {
        id,
        label: formatCpuidLabel(id),
        description: describeCpuidFeature(id),
        instructionCount: count
      };
    })
    .sort((a, b) => b.instructionCount - a.instructionCount || a.id.localeCompare(b.id));

  return {
    bitness,
    bytesSampled: data.length,
    bytesDecoded,
    instructionCount,
    invalidInstructionCount,
    instructionSets,
    issues
  };
}
