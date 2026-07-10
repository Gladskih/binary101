import { createFileRangeReader, type FileRangeReader } from "../analyzers/file-range-reader.js";
import { isPeWindowsParseResult, type PeParseResult } from "../analyzers/pe/index.js";
import type { PeWindowsParseResult } from "../analyzers/pe/core/parse-result.js";
import { PE32_OPTIONAL_HEADER_MAGIC, PE32_PLUS_OPTIONAL_HEADER_MAGIC } from "../analyzers/pe/optional-header/magic.js";
import { IMAGE_FILE_MACHINE_I386 } from "../analyzers/coff/machine.js";
import { getCanonicalPeMachine } from "../analyzers/pe/machine.js";
import { readLoadConfigPointerRva } from "../analyzers/pe/load-config/index.js";
import { PE_RVA_EXCLUSIVE_LIMIT } from "../analyzers/pe/layout/rva-limits.js";
import {
  findSectionContainingRva,
  isMemoryExecutableSection
} from "../analyzers/pe/disassembly/sampling.js";
import {
  readGuardCFFunctionTableRvas,
  readGuardEhContinuationTableRvas,
  readGuardLongJumpTargetTableRvas,
  readSafeSehHandlerTableRvas
} from "../analyzers/pe/load-config/tables.js";

type PeDisassemblySeedSet = {
  canonicalMachine: number;
  entrypointRva: number;
  exportRvas: number[];
  unwindBeginRvas: number[];
  unwindHandlerRvas: number[];
  tlsCallbackRvas: number[];
  guardCFFunctionRvas: number[];
  safeSehHandlerRvas: number[];
  extraEntrypoints: Array<{ source: string; rvas: number[] }>;
};

type ReadLoadConfigPointerSlotTargetRva = (
  reader: FileRangeReader,
  pe: PeParseResult,
  imageBase: bigint,
  pointerSlotVa: bigint
) => Promise<number | null>;

const collectMsvcRttiFunctionRvas = (pe: PeWindowsParseResult | null): number[] => {
  if (!pe?.msvcRtti) return [];
  const imageSize = pe.opt.SizeOfImage >>> 0;
  if (!imageSize) return [];
  const seen = new Set<number>();
  const rvas: number[] = [];
  pe.msvcRtti.vftables.forEach(vftable => {
    vftable.functionTargetRvas.forEach(rva => {
      if (!Number.isSafeInteger(rva) || rva <= 0 || rva >= PE_RVA_EXCLUSIVE_LIMIT) return;
      const normalized = rva >>> 0;
      if (normalized >= imageSize || seen.has(normalized)) return;
      const section = findSectionContainingRva(pe.sections, normalized);
      if (!section || !isMemoryExecutableSection(section)) return;
      seen.add(normalized);
      rvas.push(normalized);
    });
  });
  return rvas;
};

const collectBasicExtraEntrypoints = (
  windowsPe: PeWindowsParseResult | null
): Array<{ source: string; rvas: number[] }> => {
  const extraEntrypoints: Array<{ source: string; rvas: number[] }> = [];
  if (windowsPe?.goRuntime?.functions.length) {
    extraEntrypoints.push({
      source: "Go runtime functab",
      rvas: windowsPe.goRuntime.functions.map(fn => Number(fn.start - windowsPe.opt.ImageBase))
    });
  }
  const msvcRttiRvas = collectMsvcRttiFunctionRvas(windowsPe);
  if (msvcRttiRvas.length) {
    extraEntrypoints.push({ source: "MSVC RTTI vftables", rvas: msvcRttiRvas });
  }
  return extraEntrypoints;
};

const isExecutableExportRva = (pe: PeParseResult, rva: number): boolean => {
  const section = findSectionContainingRva(pe.sections, rva >>> 0);
  return section != null && isMemoryExecutableSection(section);
};

const collectBasicPeDisassemblySeeds = (
  pe: PeParseResult,
  windowsPe: PeWindowsParseResult | null
): PeDisassemblySeedSet => {
  const windowsOpt = windowsPe?.opt ?? null;
  return {
    canonicalMachine: getCanonicalPeMachine(pe.coff.Machine),
    entrypointRva: pe.opt?.AddressOfEntryPoint ?? 0,
    exportRvas: windowsPe?.exports?.entries
      ?.filter(entry => entry.rva && !entry.forwarder && isExecutableExportRva(pe, entry.rva))
      .map(entry => entry.rva >>> 0) ?? [],
    unwindBeginRvas: windowsOpt?.Magic === PE32_PLUS_OPTIONAL_HEADER_MAGIC &&
      Array.isArray(windowsPe?.exception?.beginRvas)
        ? windowsPe.exception.beginRvas.filter(rva => Number.isSafeInteger(rva) && rva > 0).map(rva => rva >>> 0)
        : [],
    unwindHandlerRvas: windowsOpt?.Magic === PE32_PLUS_OPTIONAL_HEADER_MAGIC &&
      Array.isArray(windowsPe?.exception?.handlerRvas)
        ? windowsPe.exception.handlerRvas.filter(rva => Number.isSafeInteger(rva) && rva > 0).map(rva => rva >>> 0)
        : [],
    tlsCallbackRvas: Array.isArray(windowsPe?.tls?.CallbackRvas)
      ? windowsPe.tls.CallbackRvas.filter(rva => Number.isSafeInteger(rva) && rva > 0).map(rva => rva >>> 0)
      : [],
    guardCFFunctionRvas: [],
    safeSehHandlerRvas: [],
    extraEntrypoints: collectBasicExtraEntrypoints(windowsPe)
  };
};

const readLoadConfigPointerSlotTargetRva = async (
  reader: FileRangeReader,
  pe: PeParseResult,
  imageBase: bigint,
  pointerSlotVa: bigint,
  pointerSize: number,
  readPointerVa: (view: DataView) => bigint
): Promise<number | null> => {
  const slotRva = readLoadConfigPointerRva(imageBase, pointerSlotVa);
  if (slotRva == null) return null;
  const slotOffset = pe.rvaToOff(slotRva);
  if (
    slotOffset == null ||
    !Number.isSafeInteger(slotOffset) ||
    slotOffset < 0 ||
    slotOffset + pointerSize > reader.size
  ) {
    return null;
  }
  const view = await reader.read(slotOffset, pointerSize);
  if (view.byteLength < pointerSize) return null;
  return readLoadConfigPointerRva(imageBase, readPointerVa(view));
};

// Microsoft PE format: IMAGE_LOAD_CONFIG_DIRECTORY32 uses 4-byte VA fields.
const readPe32LoadConfigPointerSlotTargetRva: ReadLoadConfigPointerSlotTargetRva = (
  reader,
  pe,
  imageBase,
  pointerSlotVa
) => readLoadConfigPointerSlotTargetRva(
  reader,
  pe,
  imageBase,
  pointerSlotVa,
  4,
  view => BigInt(view.getUint32(0, true))
);

// Microsoft PE format: IMAGE_LOAD_CONFIG_DIRECTORY64 uses 8-byte VA fields.
const readPe32PlusLoadConfigPointerSlotTargetRva: ReadLoadConfigPointerSlotTargetRva = (
  reader,
  pe,
  imageBase,
  pointerSlotVa
) => readLoadConfigPointerSlotTargetRva(
  reader,
  pe,
  imageBase,
  pointerSlotVa,
  8,
  view => view.getBigUint64(0, true)
);

const addLoadConfigPointerSeeds = async (
  seeds: PeDisassemblySeedSet,
  reader: FileRangeReader,
  pe: PeParseResult,
  imageBase: bigint,
  readPointerSlotTargetRva: ReadLoadConfigPointerSlotTargetRva,
  loadcfg: PeWindowsParseResult["loadcfg"] | undefined
): Promise<void> => {
  if (!loadcfg) return;
  const addPointerSeed = async (source: string, pointerVa: bigint | undefined): Promise<void> => {
    const rva = await readPointerSlotTargetRva(reader, pe, imageBase, pointerVa ?? 0n);
    if (rva != null) seeds.extraEntrypoints.push({ source, rvas: [rva] });
  };
  await addPointerSeed("GuardCF check function", loadcfg.GuardCFCheckFunctionPointer);
  await addPointerSeed("GuardCF dispatch function", loadcfg.GuardCFDispatchFunctionPointer);
  await addPointerSeed("GuardXFG check function", loadcfg.GuardXFGCheckFunctionPointer);
  await addPointerSeed("GuardXFG dispatch function", loadcfg.GuardXFGDispatchFunctionPointer);
  await addPointerSeed(
    "GuardXFG table dispatch function",
    loadcfg.GuardXFGTableDispatchFunctionPointer
  );
  await addPointerSeed("Guard memcpy function", loadcfg.GuardMemcpyFunctionPointer);
};

const addGuardEhContinuationSeeds = async (
  seeds: PeDisassemblySeedSet,
  reader: FileRangeReader,
  pe: PeParseResult,
  windowsPe: PeWindowsParseResult
): Promise<void> => {
  const rvas = windowsPe.loadcfg?.tables?.guardEhContinuation?.entries.map(entry => entry.rva) ??
    (windowsPe.loadcfg
      ? await readGuardEhContinuationTableRvas(
        reader,
        pe.rvaToOff,
        windowsPe.opt.ImageBase,
        windowsPe.loadcfg.GuardEHContinuationTable,
        windowsPe.loadcfg.GuardEHContinuationCount,
        windowsPe.loadcfg.GuardFlags
      ).catch(() => [])
      : []);
  if (rvas.length) seeds.extraEntrypoints.push({ source: "GuardEH continuation", rvas });
};

const addGuardLongJumpTargetSeeds = async (
  seeds: PeDisassemblySeedSet,
  reader: FileRangeReader,
  pe: PeParseResult,
  windowsPe: PeWindowsParseResult
): Promise<void> => {
  const rvas = windowsPe.loadcfg?.tables?.guardLongJumpTarget?.entries.map(entry => entry.rva) ??
    (windowsPe.loadcfg
      ? await readGuardLongJumpTargetTableRvas(
        reader,
        pe.rvaToOff,
        windowsPe.opt.ImageBase,
        windowsPe.loadcfg.GuardLongJumpTargetTable,
        windowsPe.loadcfg.GuardLongJumpTargetCount,
        windowsPe.loadcfg.GuardFlags
      ).catch(() => [])
      : []);
  if (rvas.length) seeds.extraEntrypoints.push({ source: "Guard longjmp target", rvas });
};

const addLoadConfigTableSeeds = async (
  seeds: PeDisassemblySeedSet,
  reader: FileRangeReader,
  pe: PeParseResult,
  windowsPe: PeWindowsParseResult | null
): Promise<void> => {
  const windowsOpt = windowsPe?.opt ?? null;
  seeds.guardCFFunctionRvas = windowsPe?.loadcfg?.tables?.guardFid?.entries.map(entry => entry.rva) ??
    (windowsPe?.loadcfg
      ? await readGuardCFFunctionTableRvas(
        reader,
        pe.rvaToOff,
        windowsPe.opt.ImageBase,
        windowsPe.loadcfg.GuardCFFunctionTable,
        windowsPe.loadcfg.GuardCFFunctionCount,
        windowsPe.loadcfg.GuardFlags
      ).catch(() => [])
      : []);
  seeds.safeSehHandlerRvas = windowsPe?.loadcfg?.tables?.safeSehHandler?.entries.map(entry => entry.rva) ??
    (seeds.canonicalMachine === IMAGE_FILE_MACHINE_I386 &&
      windowsOpt?.Magic === PE32_OPTIONAL_HEADER_MAGIC &&
      windowsPe?.loadcfg
      ? await readSafeSehHandlerTableRvas(
        reader,
        pe.rvaToOff,
        windowsPe.opt.ImageBase,
        windowsPe.loadcfg.SEHandlerTable,
        windowsPe.loadcfg.SEHandlerCount
      ).catch(() => [])
      : []);
  if (!windowsPe) return;
  await addGuardEhContinuationSeeds(seeds, reader, pe, windowsPe);
  await addGuardLongJumpTargetSeeds(seeds, reader, pe, windowsPe);
};

const collectPeDisassemblySeeds = async (
  file: File,
  pe: PeParseResult
): Promise<PeDisassemblySeedSet> => {
  const reader = createFileRangeReader(file, 0, file.size);
  const windowsPe = isPeWindowsParseResult(pe) ? pe : null;
  const seeds = collectBasicPeDisassemblySeeds(pe, windowsPe);
  await addLoadConfigPointerSeeds(
    seeds,
    reader,
    pe,
    windowsPe?.opt.ImageBase ?? 0n,
    windowsPe?.opt.Magic === PE32_PLUS_OPTIONAL_HEADER_MAGIC
      ? readPe32PlusLoadConfigPointerSlotTargetRva
      : readPe32LoadConfigPointerSlotTargetRva,
    windowsPe?.loadcfg ?? undefined
  );
  await addLoadConfigTableSeeds(seeds, reader, pe, windowsPe);
  return seeds;
};

export { collectPeDisassemblySeeds };
export type { PeDisassemblySeedSet };
