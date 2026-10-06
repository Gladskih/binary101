import type { FileRangeReader } from "../../file-range-reader.js";
import type { PeWindowsParseResult } from "../core/parse-result.js";
import type { PeClrReadyToRunSectionData, PeClrReadyToRunThunk } from "./ready-to-run-types.js";
import { readyToRunImageSections } from "./ready-to-run-image-sections.js";
import { decodeReadyToRunThunkSection } from "./ready-to-run-thunks.js";
import { getCanonicalPeMachine } from "../machine.js";
import { findSectionContainingRva, isMemoryExecutableSection } from "../disassembly/sampling.js";
import { isRvaRange, mappedRvaSize } from "../rva-mapping.js";

export const decodeReadyToRunThunks = async (
  reader: FileRangeReader, pe: PeWindowsParseResult
): Promise<void> => {
  const data = pe.clr?.readyToRun ?? pe.readyToRun;
  if (data?.status !== "ready-to-run") return;
  const cache = new Map<string, PeClrReadyToRunSectionData>();
  const sections = readyToRunImageSections(data).filter(section =>
    section.type === 106 && section.decoded?.kind !== "thunks");
  for (const section of sections) {
    const key = `${section.rva}/${section.size}`;
    section.decoded = cache.get(key) ?? { kind: "thunks", entries: await decodeReadyToRunThunkSection(
      reader, pe.rvaToOff, section, getCanonicalPeMachine(pe.coff.Machine), pe.opt.ImageBase, data.issues) };
    cache.set(key, section.decoded);
  }
};

const isThunkCode = (thunk: PeClrReadyToRunThunk, pe: PeWindowsParseResult, fileSize: number): boolean => {
  if (!thunk.rva || !isRvaRange(thunk.rva, thunk.size) || thunk.rva + thunk.size > pe.opt.SizeOfImage) return false;
  const section = findSectionContainingRva(pe.sections, thunk.rva);
  return section != null && isMemoryExecutableSection(section) &&
    thunk.rva - section.virtualAddress + thunk.size <= section.sizeOfRawData &&
    mappedRvaSize(pe.rvaToOff, thunk.rva, thunk.size, fileSize) === thunk.size;
};

export const collectReadyToRunThunkRvas = (
  pe: PeWindowsParseResult, fileSize: number, issues: string[]
): number[] => {
  const data = pe.clr?.readyToRun ?? pe.readyToRun;
  if (data?.status !== "ready-to-run") return [];
  const rvas = new Set<number>();
  const thunks = readyToRunImageSections(data).flatMap(section =>
    section.decoded?.kind === "thunks" ? section.decoded.entries : []);
  for (const thunk of thunks) {
    if (isThunkCode(thunk, pe, fileSize)) rvas.add(thunk.rva);
    else issues.push(`ReadyToRun thunk at 0x${thunk.rva.toString(16)} is not file-backed executable code.`);
  }
  return [...rvas];
};
