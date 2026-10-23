import type { FileRangeReader } from "../../file-range-reader.js";
import type { RvaToOffset } from "../types.js";
import { getReadableDebugData } from "./data.js";
import { readDebugPayload } from "./payload-reader.js";
import { LegacyCodeViewReader } from "./legacy-codeview-reader.js";
import type { LegacyCodeViewData, PeLegacyCodeViewInfo } from "./legacy-codeview.js";
import type { LegacyCodeViewSubsection } from "./legacy-codeview-directory.js";
import { readHllDirectory, readHllModule, type HllModule } from "./hll-directory.js";
import { readHllSymbols } from "./hll-symbols.js";
import { readHllTypes } from "./hll-type-records.js";
import { readHllSource } from "./hll-source.js";
import { readCodeViewC6Symbols } from "./codeview-c6-symbols.js";
import { readCodeViewC6Types } from "./codeview-c6-type-records.js";
import { readCodeViewCv3SourceLines } from "./codeview-cv3.js";
import { readLegacyCodeViewModuleSymbols } from "./legacy-codeview-symbols.js";
import { readLegacyCodeViewModuleTypes } from "./legacy-codeview-type-records.js";
import { readLegacyCodeViewLibraries } from "./legacy-codeview-modules.js";
import { readLegacyCodeViewPublics, readLegacyCodeViewOldLines } from "./legacy-codeview-compatibility.js";

const decodeCodeViewStream = async (reader: LegacyCodeViewReader, type: number): Promise<LegacyCodeViewData> => {
  // The NB04 envelope can contain C7 or C6 streams. Open Watcom's linker retains
  // a C7 stream's signature even when it emits style/version zero in the module.
  // https://github.com/open-watcom/open-watcom-v2/blob/065b3083b9f06919c871c67ce608e3b29674ffce/bld/wl/c/dbghll.c
  const signature = reader.size >= 4 ? await reader.uint32(0) : 0;
  if ([1, 2, 4].includes(signature)) {
    return type === 0x104 ? readLegacyCodeViewModuleSymbols(reader) : readLegacyCodeViewModuleTypes(reader);
  }
  return type === 0x104 ? readCodeViewC6Symbols(reader) : readCodeViewC6Types(reader);
};

const decodeModuleStream = async (reader: LegacyCodeViewReader, type: number,
  module: HllModule | undefined): Promise<LegacyCodeViewData> => {
  if (!module) throw new Error("HLL subsection has no readable module descriptor.");
  if (module.style === "HL") return type === 0x104 ? readHllSymbols(reader) : readHllTypes(reader, module.version);
  if (module.style !== "CV" && module.style !== "\0\0") throw new Error(`Unknown HLL module style ${module.style}.`);
  return decodeCodeViewStream(reader, type);
};

const DECODERS: Partial<Record<number, (reader: LegacyCodeViewReader) => Promise<LegacyCodeViewData>>> = {
  0x101: readHllModule, 0x102: readLegacyCodeViewPublics, 0x106: readLegacyCodeViewLibraries,
  0x105: readCodeViewCv3SourceLines, 0x109: readLegacyCodeViewOldLines
};

const decodeSubsection = async (reader: LegacyCodeViewReader, entry: LegacyCodeViewSubsection,
  modules: Map<number, HllModule>): Promise<LegacyCodeViewData | undefined> => {
  const source = reader.subsection(entry.offset, entry.size);
  if (entry.offset < 8 || entry.size > reader.size - entry.offset) {
    throw new Error("HLL subsection lies outside payload bounds.");
  }
  if (entry.type === 0x10b) return readHllSource(source, modules.get(entry.module)?.version ?? 0);
  if (entry.type === 0x103 || entry.type === 0x104) {
    return decodeModuleStream(source, entry.type, modules.get(entry.module));
  }
  return DECODERS[entry.type]?.(source);
};

const readContents = async (source: LegacyCodeViewReader, offset: number): Promise<PeLegacyCodeViewInfo> => {
  const directory = await readHllDirectory(source, offset);
  const modules = new Map<number, HllModule>();
  const subsections: PeLegacyCodeViewInfo["directories"][number]["subsections"] = [];
  const decoded = new Map<string, LegacyCodeViewData | undefined>();
  // Module styles are needed even if a producer orders the directory differently.
  const entries = [...directory.entries.filter(entry => entry.type === 0x101),
    ...directory.entries.filter(entry => entry.type !== 0x101)];
  const dataByEntry = new Map<LegacyCodeViewSubsection, LegacyCodeViewData>();
  for (const entry of entries) {
    try {
      const key = `${entry.type}:${entry.module}:${entry.offset}:${entry.size}`;
      if (!decoded.has(key)) decoded.set(key, await decodeSubsection(source, entry, modules));
      const data = decoded.get(key);
      if (!data) continue;
      if (data.kind === "module") modules.set(entry.module, data as HllModule);
      dataByEntry.set(entry, data);
    } catch (error) {
      source.warn(`HLL subsection ${entry.type}, module ${entry.module}: ${String(error)}`);
    }
  }
  for (const entry of directory.entries) {
    const data = dataByEntry.get(entry);
    subsections.push(data ? { ...entry, data } : entry);
  }
  return { signature: "NB04", directories: [{ flags: 0, subsections }] };
};

const payloadContents = async (reader: LegacyCodeViewReader): Promise<LegacyCodeViewReader> => {
  if (reader.size < 16) return reader;
  const footer = await reader.view(reader.size - 8, 8);
  if (footer.getUint32(0, true) !== 0x3430424e) return reader;
  if (footer.getUint32(4, true) !== reader.size) reader.warn("HLL trailer backward distance does not match its payload.");
  return reader.subsection(0, reader.size - 8);
};

export const parseHll = async (reader: FileRangeReader, fileSize: number, rvaToOff: RvaToOffset,
  address: number, pointer: number, size: number,
  warn: (message: string) => void): Promise<PeLegacyCodeViewInfo | null> => {
  const location = getReadableDebugData("HLL", fileSize, rvaToOff, address, pointer, size, warn);
  if (!location) return null;
  const source = new LegacyCodeViewReader(location.size, (offset, count) =>
    readDebugPayload(reader, rvaToOff, address, pointer, offset, count), warn);
  try {
    const header = await source.view(0, 8);
    if (header.getUint32(0, true) !== 0x3430424e) throw new Error("Unsupported HLL signature.");
    return await readContents(await payloadContents(source), header.getUint32(4, true));
  } catch (error) { warn(String(error)); return null; }
};
