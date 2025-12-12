"use strict";

import type { PeSection, RvaToOffset } from "./types.js";

export interface PeInstructionSetUsage {
  id: string;
  label: string;
  description: string;
  instructionCount: number;
}

export interface PeInstructionSetReport {
  bitness: 32 | 64;
  bytesAnalyzed: number;
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

const MAX_DECODE_BYTES = 256 * 1024;
const MAX_INSTRUCTIONS = 20_000;
const MAX_CONSECUTIVE_INVALID = 128;

const formatCpuidLabel = (name: string): string => {
  if (name === "X64") return "x86-64";
  if (name.startsWith("AVX512_")) return `AVX-512 ${name.slice("AVX512_".length).replaceAll("_", " ")}`;
  if (name.startsWith("AVX10_")) return `AVX10 ${name.slice("AVX10_".length).replaceAll("_", " ")}`;
  if (/^SSE4_[12]$/.test(name)) return name.replace("_", ".");
  return name;
};

const CPUID_DESCRIPTIONS: Record<string, string> = {
  X64: "x86-64 long mode (64-bit registers and addressing).",
  SSE: "Streaming SIMD Extensions (128-bit SIMD instructions).",
  SSE2: "SSE2 SIMD (128-bit integer + double-precision); baseline on x86-64.",
  SSE3: "SSE3 extensions (mostly SIMD horizontal/complex ops).",
  SSSE3: "Supplemental SSE3 (byte-shuffle and other SIMD extensions).",
  SSE4_1: "SSE4.1 SIMD extensions (dot products, blends, etc.).",
  SSE4_2: "SSE4.2 SIMD extensions (string/CRC-related instructions).",
  AVX: "Advanced Vector Extensions (VEX encoding, 256-bit YMM registers).",
  AVX2: "AVX2 integer 256-bit SIMD extensions (incl. gathers).",
  FMA: "FMA3 fused multiply-add (floating point).",
  BMI1: "Bit Manipulation Instructions 1 (e.g., ANDN, BEXTR).",
  BMI2: "Bit Manipulation Instructions 2 (e.g., MULX, PDEP/PEXT).",
  AES: "AES-NI crypto instructions (AES rounds).",
  PCLMULQDQ: "Carry-less multiply (GF(2) multiply; used in GCM/CRC).",
  POPCNT: "Population count instruction.",
  LZCNT: "Leading zero count (ABM/LZCNT).",
  SHA: "SHA extensions (SHA1/SHA256 rounds).",
  AVX512F: "AVX-512 Foundation (512-bit ZMM registers).",
  AVX512VL: "AVX-512 Vector Length extensions (128/256-bit forms).",
  AVX512BW: "AVX-512 Byte/Word instructions.",
  AVX512DQ: "AVX-512 Doubleword/Quadword instructions.",
  AVX512CD: "AVX-512 Conflict Detection (CD).",
  AVX512_VBMI: "AVX-512 VBMI (Vector Byte Manipulation Instructions).",
  AVX512_VBMI2: "AVX-512 VBMI2 (additional byte manipulation).",
  AVX512_VNNI: "AVX-512 VNNI (integer dot-product for ML).",
  AVX512_BITALG: "AVX-512 BITALG (bit algorithms).",
  AVX512_VPOPCNTDQ: "AVX-512 VPOPCNTDQ (vector popcount)."
};

const describeCpuidFeature = (name: string): string => {
  const known = CPUID_DESCRIPTIONS[name];
  if (known) return known;
  if (name.startsWith("AVX512_")) return "AVX-512 extension (subset; typically requires AVX512F).";
  if (name.startsWith("AVX10_")) return "AVX10 extension (newer AVX family).";
  if (name.startsWith("AVX")) return "Advanced Vector Extensions family feature.";
  if (name.startsWith("SSE")) return "SSE family SIMD extension.";
  if (name.endsWith("_ONLY")) return "CPU-specific/legacy-only instruction variant.";
  return "CPUID feature flag required by at least one decoded instruction.";
};

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

export async function analyzePeInstructionSets(
  file: File,
  opts: AnalyzePeInstructionSetOptions
): Promise<PeInstructionSetReport> {
  const issues: string[] = [];
  const coffMachine = opts.coffMachine >>> 0;
  const supported = coffMachine === IMAGE_FILE_MACHINE_I386 || coffMachine === IMAGE_FILE_MACHINE_AMD64;
  const bitness: 32 | 64 = opts.is64Bit ? 64 : 32;

  if (!supported) {
    issues.push(
      `Disassembly is only supported for x86/x86-64 (Machine ${coffMachine.toString(16)}).`
    );
    return {
      bitness,
      bytesAnalyzed: 0,
      instructionCount: 0,
      invalidInstructionCount: 0,
      instructionSets: [],
      issues
    };
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
      return {
        bitness,
        bytesAnalyzed: 0,
        instructionCount: 0,
        invalidInstructionCount: 0,
        instructionSets: [],
        issues
      };
    }
    startRva = section.virtualAddress >>> 0;
    startOffset = section.pointerToRawData >>> 0;
    issues.push(`Falling back to section ${section.name || "(unnamed)"} for disassembly sample.`);
  }

  const sectionEnd = section
    ? Math.min(file.size, (section.pointerToRawData >>> 0) + (section.sizeOfRawData >>> 0))
    : file.size;
  const sliceEnd = Math.min(sectionEnd, startOffset + MAX_DECODE_BYTES);
  if (startOffset >= file.size || sliceEnd <= startOffset) {
    issues.push("No bytes available at selected disassembly start offset.");
    return {
      bitness,
      bytesAnalyzed: 0,
      instructionCount: 0,
      invalidInstructionCount: 0,
      instructionSets: [],
      issues
    };
  }

  const data = new Uint8Array(await file.slice(startOffset, sliceEnd).arrayBuffer());
  if (data.length === 0) {
    issues.push("Disassembly sample is empty after bounds checks.");
    return {
      bitness,
      bytesAnalyzed: 0,
      instructionCount: 0,
      invalidInstructionCount: 0,
      instructionSets: [],
      issues
    };
  }

  let iced: IcedX86Module;
  try {
    iced = (await import("iced-x86")) as unknown as IcedX86Module;
  } catch (err) {
    issues.push(`Failed to load iced-x86 disassembler (${String(err)})`);
    return {
      bitness,
      bytesAnalyzed: data.length,
      instructionCount: 0,
      invalidInstructionCount: 0,
      instructionSets: [],
      issues
    };
  }
  const { Code, CpuidFeature, Decoder, DecoderOptions } = iced;

  const featureCounts = new Map<number, number>();
  let instructionCount = 0;
  let invalidInstructionCount = 0;
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
      if (instr.code === Code["INVALID"] || instr.length === 0) {
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
      if (instructionCount >= MAX_INSTRUCTIONS) {
        issues.push(`Stopping after ${MAX_INSTRUCTIONS} instructions (analysis limit).`);
        break;
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
    bytesAnalyzed: data.length,
    instructionCount,
    invalidInstructionCount,
    instructionSets,
    issues
  };
}
