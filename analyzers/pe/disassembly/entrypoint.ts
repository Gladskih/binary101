"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import { isIcedX86Module, type IcedX86Module } from "../../x86/disassembly-iced.js";
import type { PeSection } from "../types.js";
import { loadIcedX86 } from "#iced-x86-loader";
import { peSectionNameValue } from "../sections/name.js";
import type {
  AnalyzePeEntrypointDisassemblyOptions,
  PeEntrypointDisassemblyReport,
  PeEntrypointInstruction
} from "./types.js";
import {
  IMAGE_SCN_MEM_EXECUTE,
  MAX_RVA,
  RVA_EXCLUSIVE_LIMIT,
  type ValidEntrypointMetadata,
  emptyEntrypointReport,
  getHeaderRvaLimit,
  validateEntrypointMetadata
} from "./entrypoint-metadata.js";

type IcedInstruction = InstanceType<IcedX86Module["Instruction"]>;
type IcedFormatter = { format(instruction: IcedInstruction): string; free(): void };
type EntrypointIcedModule = IcedX86Module & {
  Formatter: new (syntax: number) => IcedFormatter;
  FormatterSyntax: { Nasm: number };
};
type IcedLoader = () => Promise<unknown>;
type MappedEntrypoint = {
  fileOffsetStart: number;
  rvaStart: number;
  data: Uint8Array<ArrayBufferLike>;
};

// UI preview cap: enough for entry stubs/prologues while avoiding accidental long linear sweeps.
const ENTRYPOINT_PREVIEW_LIMIT = 64;

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null;

const isEntrypointIcedModule = (value: unknown): value is EntrypointIcedModule => {
  if (!isRecord(value) || !isIcedX86Module(value)) return false;
  const module = value as IcedX86Module & Record<string, unknown>;
  const formatterSyntax = module["FormatterSyntax"];
  return (
    isRecord(formatterSyntax) &&
    typeof formatterSyntax["Nasm"] === "number" &&
    typeof module["Formatter"] === "function"
  );
};

const safeFree = (resource: { free(): void } | null | undefined): void => {
  if (!resource) return;
  try {
    resource.free();
  } catch {
    // iced-x86 cleanup is best-effort; cleanup failures must not hide analysis notes.
  }
};

const getMappedSectionSpan = (section: PeSection): number =>
  (section.virtualSize >>> 0) || (section.sizeOfRawData >>> 0);

const findSectionContainingRva = (sections: PeSection[], rva: number): PeSection | null => {
  for (const section of sections) {
    const start = section.virtualAddress >>> 0;
    const size = getMappedSectionSpan(section);
    const end = Math.min(RVA_EXCLUSIVE_LIMIT, start + size);
    if (rva >= start && rva < end) return section;
  }
  return null;
};

const toRva = (ip: bigint, imageBase: bigint): number | null => {
  if (ip < imageBase) return null;
  const delta = ip - imageBase;
  if (delta > BigInt(MAX_RVA)) return null;
  const value = Number(delta);
  return Number.isSafeInteger(value) && value >= 0 ? value >>> 0 : null;
};

const loadSectionEntrypointBytes = async (
  reader: FileRangeReader,
  opts: AnalyzePeEntrypointDisassemblyOptions,
  section: PeSection,
  rva: number,
  issues: string[]
): Promise<MappedEntrypoint | null> => {
  const sectionRva = section.virtualAddress >>> 0;
  const offsetInSection = rva - sectionRva;
  const mappedAvailable = getMappedSectionSpan(section) - offsetInSection;
  const fileOffsetStart = opts.rvaToOff(rva);
  const rawStart = section.pointerToRawData >>> 0;
  const rawEnd = rawStart + (section.sizeOfRawData >>> 0);
  if (
    fileOffsetStart == null ||
    !Number.isSafeInteger(fileOffsetStart) ||
    fileOffsetStart < rawStart ||
    fileOffsetStart >= rawEnd ||
    mappedAvailable <= 0
  ) {
    issues.push("Entry point maps outside the section bytes stored in the file.");
    return null;
  }
  const rawAvailable = rawEnd - fileOffsetStart;
  const readableSize = Math.min(mappedAvailable, rawAvailable, reader.size - fileOffsetStart);
  if (readableSize <= 0) {
    issues.push("No file bytes are available at the mapped entry point.");
    return null;
  }
  return {
    fileOffsetStart,
    rvaStart: rva >>> 0,
    data: await reader.readBytes(fileOffsetStart, readableSize)
  };
};

const loadHeaderEntrypointBytes = async (
  reader: FileRangeReader,
  opts: AnalyzePeEntrypointDisassemblyOptions,
  rva: number,
  issues: string[]
): Promise<MappedEntrypoint | null> => {
  const headerRvaLimit = getHeaderRvaLimit(opts);
  if (headerRvaLimit <= rva) {
    issues.push("Entry point is not inside a section or the mapped PE headers.");
    return null;
  }
  const fileOffsetStart = opts.rvaToOff(rva);
  if (
    fileOffsetStart == null ||
    !Number.isSafeInteger(fileOffsetStart) ||
    fileOffsetStart < 0 ||
    fileOffsetStart >= reader.size
  ) {
    issues.push("Entry point RVA could not be mapped to a file offset.");
    return null;
  }
  // Microsoft PE format: header-resident entrypoints are mapped only through SizeOfHeaders.
  const readableSize = Math.min(headerRvaLimit - rva, reader.size - fileOffsetStart);
  return {
    fileOffsetStart,
    rvaStart: rva >>> 0,
    data: await reader.readBytes(fileOffsetStart, readableSize)
  };
};

const loadEntrypointBytes = async (
  reader: FileRangeReader,
  opts: AnalyzePeEntrypointDisassemblyOptions,
  rva: number,
  issues: string[]
): Promise<MappedEntrypoint | null> => {
  const section = findSectionContainingRva(opts.sections, rva);
  if (!section) return loadHeaderEntrypointBytes(reader, opts, rva, issues);
  if ((section.characteristics & IMAGE_SCN_MEM_EXECUTE) === 0) {
    issues.push(
      `Entry point is inside non-executable section ${peSectionNameValue(section.name)}; disassembly skipped.`
    );
    return null;
  }
  return loadSectionEntrypointBytes(reader, opts, section, rva, issues);
};

const decodeEntrypointPreview = (
  iced: EntrypointIcedModule,
  opts: AnalyzePeEntrypointDisassemblyOptions,
  metadata: ValidEntrypointMetadata,
  mapped: MappedEntrypoint,
  issues: string[]
): Pick<PeEntrypointDisassemblyReport, "bytesDecoded" | "instructions"> => {
  const decoder = new iced.Decoder(metadata.bitness, mapped.data, iced.DecoderOptions.None);
  const formatter = new iced.Formatter(iced.FormatterSyntax.Nasm);
  const instr = new iced.Instruction();
  const instructions: PeEntrypointInstruction[] = [];
  let bytesDecoded = 0;
  let recordedStopReason = false;
  try {
    decoder.position = 0;
    decoder.ip = BigInt.asUintN(64, opts.imageBase + BigInt(mapped.rvaStart));
    for (let index = 0; index < ENTRYPOINT_PREVIEW_LIMIT && decoder.canDecode; index += 1) {
      decoder.decodeOut(instr);
      const rva = toRva(instr.ip, opts.imageBase);
      if (rva == null || instr.length <= 0 || instr.code === iced.Code["INVALID"]) {
        issues.push("Entrypoint preview stopped at an invalid or zero-length instruction.");
        recordedStopReason = true;
        break;
      }
      const offsetInPreview = rva - mapped.rvaStart;
      if (offsetInPreview < 0 || instr.length > mapped.data.length - offsetInPreview) {
        issues.push("Entrypoint preview stopped at the readable byte boundary.");
        recordedStopReason = true;
        break;
      }
      const text = formatter.format(instr);
      instructions.push({
        rva,
        fileOffset: mapped.fileOffsetStart + offsetInPreview,
        text
      });
      bytesDecoded += instr.length;
      if (instr.flowControl !== iced.FlowControl["Next"]) {
        issues.push(`Entrypoint preview stopped at control-flow instruction '${text}'.`);
        recordedStopReason = true;
        break;
      }
    }
    if (instructions.length >= ENTRYPOINT_PREVIEW_LIMIT) {
      issues.push(`Entrypoint preview capped at ${ENTRYPOINT_PREVIEW_LIMIT} instructions.`);
    } else if (!recordedStopReason && instructions.length > 0 && !decoder.canDecode) {
      issues.push("Entrypoint preview stopped at the readable byte boundary.");
    }
    return { bytesDecoded, instructions };
  } finally {
    safeFree(instr);
    safeFree(formatter);
    safeFree(decoder);
  }
};

export async function analyzePeEntrypointDisassembly(
  reader: FileRangeReader,
  opts: AnalyzePeEntrypointDisassemblyOptions,
  loader: IcedLoader = loadIcedX86
): Promise<PeEntrypointDisassemblyReport> {
  const issues: string[] = [];
  const metadata = validateEntrypointMetadata(opts, issues);
  if (!metadata) return emptyEntrypointReport(opts, issues);
  let mapped: MappedEntrypoint | null;
  try {
    mapped = await loadEntrypointBytes(reader, opts, metadata.entrypointRva, issues);
  } catch (error) {
    issues.push(`Entrypoint byte loading failed (${String(error)})`);
    return emptyEntrypointReport(opts, issues);
  }
  if (!mapped) return emptyEntrypointReport(opts, issues);
  if (mapped.data.length === 0) {
    issues.push("No file bytes are available at the mapped entry point.");
    return emptyEntrypointReport(opts, issues);
  }
  let loaded: unknown;
  try {
    loaded = await loader();
  } catch (error) {
    issues.push(`Failed to load iced-x86 disassembler (${String(error)})`);
    return emptyEntrypointReport(opts, issues);
  }
  if (!isEntrypointIcedModule(loaded)) {
    issues.push("Failed to load iced-x86 disassembler (unexpected module shape).");
    return emptyEntrypointReport(opts, issues);
  }
  try {
    return {
      bitness: metadata.bitness,
      entrypointRva: metadata.entrypointRva,
      ...decodeEntrypointPreview(loaded, opts, metadata, mapped, issues),
      issues
    };
  } catch (error) {
    issues.push(`Entrypoint disassembly failed (${String(error)})`);
    return emptyEntrypointReport(opts, issues);
  }
}
