import type { FileRangeReader } from "../analyzers/file-range-reader.js";
import type { PeParseResult } from "../analyzers/pe/index.js";
import type { PeWindowsParseResult } from "../analyzers/pe/core/parse-result.js";
import { readLoadConfigPointerRva } from "../analyzers/pe/load-config/index.js";
import {
  findSectionContainingRva, isMemoryExecutableSection
} from "../analyzers/pe/disassembly/sampling.js";

const readSlotTarget = async (
  reader: FileRangeReader,
  pe: PeParseResult,
  imageBase: bigint,
  slotVa: bigint,
  pointerSize: 4 | 8
): Promise<number | null> => {
  const slotRva = readLoadConfigPointerRva(imageBase, slotVa);
  if (slotRva == null) return null;
  const slotOffset = pe.rvaToOff(slotRva);
  if (slotOffset == null || !Number.isSafeInteger(slotOffset) || slotOffset < 0 ||
    slotOffset + pointerSize > reader.size) return null;
  const view = await reader.read(slotOffset, pointerSize);
  if (view.byteLength < pointerSize) return null;
  // Microsoft PE format: IMAGE_LOAD_CONFIG_DIRECTORY32/64 store 4/8-byte VAs.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
  const targetVa = pointerSize === 4
    ? BigInt(view.getUint32(0, true)) : view.getBigUint64(0, true);
  return readLoadConfigPointerRva(imageBase, targetVa);
};

export const collectLoadConfigPointerSeeds = async (
  reader: FileRangeReader,
  pe: PeParseResult,
  imageBase: bigint,
  pointerSize: 4 | 8,
  loadcfg: PeWindowsParseResult["loadcfg"] | undefined
): Promise<Array<{ source: string; rvas: number[] }>> => {
  if (!loadcfg) return [];
  const seeds: Array<{ source: string; rvas: number[] }> = [];
  const failureRva = readLoadConfigPointerRva(imageBase, loadcfg.GuardRFFailureRoutine ?? 0n);
  const section = failureRva == null ? null : findSectionContainingRva(pe.sections, failureRva);
  if (failureRva != null && section && isMemoryExecutableSection(section)) {
    seeds.push({ source: "GuardRF failure routine", rvas: [failureRva] });
  }
  const slots: Array<[string, bigint | undefined]> = [
    ["GuardCF check function", loadcfg.GuardCFCheckFunctionPointer],
    ["GuardCF dispatch function", loadcfg.GuardCFDispatchFunctionPointer],
    ["GuardXFG check function", loadcfg.GuardXFGCheckFunctionPointer],
    ["GuardXFG dispatch function", loadcfg.GuardXFGDispatchFunctionPointer],
    ["GuardXFG table dispatch function", loadcfg.GuardXFGTableDispatchFunctionPointer],
    ["Guard memcpy function", loadcfg.GuardMemcpyFunctionPointer],
    ["GuardRF failure function", loadcfg.GuardRFFailureRoutineFunctionPointer],
    ["GuardRF verify stack pointer function", loadcfg.GuardRFVerifyStackPointerFunctionPointer]
  ];
  for (const [source, slotVa] of slots) {
    const rva = await readSlotTarget(reader, pe, imageBase, slotVa ?? 0n, pointerSize);
    if (rva != null) seeds.push({ source, rvas: [rva] });
  }
  return seeds;
};
