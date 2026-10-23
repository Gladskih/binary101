import type { FileRangeReader } from "../../file-range-reader.js";
import type { RvaToOffset } from "../types.js";
import { getReadableDebugData } from "./data.js";
import { readDebugPayload } from "./payload-reader.js";
import { LegacyCodeViewReader } from "./legacy-codeview-reader.js";
import { readCodeViewC6Directories, CODEVIEW_C6_DECODERS } from "./codeview-c6.js";
import { readLegacyCodeViewDirectories, type LegacyCodeViewSubsection } from "./legacy-codeview-directory.js";
import { readLegacyCodeViewModule, readLegacyCodeViewLibraries, readLegacyCodeViewSegmentNames,
  readLegacyCodeViewSegmentMap, readLegacyCodeViewFiles, type LegacyCodeViewModule,
  type LegacyCodeViewLibraries, type LegacyCodeViewSegmentNames, type LegacyCodeViewSegmentMap,
  type LegacyCodeViewFiles } from "./legacy-codeview-modules.js";
import { readLegacyCodeViewSource, type LegacyCodeViewSource } from "./legacy-codeview-source.js";
import { readLegacyCodeViewGlobalSymbols, readLegacyCodeViewModuleSymbols,
  type LegacyCodeViewSymbols } from "./legacy-codeview-symbols.js";
import { readLegacyCodeViewGlobalTypes, readLegacyCodeViewModuleTypes,
  type LegacyCodeViewTypes } from "./legacy-codeview-type-records.js";
import { readLegacyCodeViewPublics, readLegacyCodeViewOldLines, readLegacyCodeViewFrameMap,
  type LegacyCodeViewPublics, type LegacyCodeViewOldLines, type LegacyCodeViewFrameMap } from "./legacy-codeview-compatibility.js";

export type LegacyCodeViewData = LegacyCodeViewModule | LegacyCodeViewLibraries | LegacyCodeViewSegmentNames |
  LegacyCodeViewSegmentMap | LegacyCodeViewFiles | LegacyCodeViewSource | LegacyCodeViewSymbols | LegacyCodeViewTypes |
  LegacyCodeViewPublics | LegacyCodeViewOldLines | LegacyCodeViewFrameMap;
export interface PeLegacyCodeViewInfo {
  signature: string;
  directories: { flags: number; subsections: (LegacyCodeViewSubsection & { data?: LegacyCodeViewData })[] }[];
}

const DECODERS: Partial<Record<number, (reader: LegacyCodeViewReader) => Promise<LegacyCodeViewData>>> = {
  ...CODEVIEW_C6_DECODERS,
  0x120: readLegacyCodeViewModule, 0x121: readLegacyCodeViewModuleTypes,
  0x122: readLegacyCodeViewPublics, 0x126: readLegacyCodeViewOldLines,
  0x123: readLegacyCodeViewModuleSymbols, 0x124: readLegacyCodeViewModuleSymbols,
  0x125: readLegacyCodeViewModuleSymbols, 0x127: readLegacyCodeViewSource, 0x128: readLegacyCodeViewLibraries,
  0x129: readLegacyCodeViewGlobalSymbols, 0x12a: readLegacyCodeViewGlobalSymbols,
  0x12d: readLegacyCodeViewSegmentMap,
  0x12c: readLegacyCodeViewFrameMap, 0x12f: readLegacyCodeViewModuleTypes,
  0x12e: readLegacyCodeViewSegmentNames, 0x133: readLegacyCodeViewFiles, 0x134: readLegacyCodeViewGlobalSymbols
};

const decodeSubsection = async (reader: LegacyCodeViewReader, entry: LegacyCodeViewSubsection, signature: string,
  decoded: Map<string, LegacyCodeViewData | undefined>) => {
  const decode = entry.type === 0x12b
    ? (source: LegacyCodeViewReader) => readLegacyCodeViewGlobalTypes(source, signature) : DECODERS[entry.type];
  try {
    if (entry.offset > reader.size || entry.size > reader.size - entry.offset) {
      throw new Error("CodeView subsection lies outside payload bounds.");
    }
    const key = `${entry.type}:${entry.offset}:${entry.size}`;
    if (!decoded.has(key)) {
      decoded.set(key, undefined);
      if (decode) decoded.set(key, await decode(reader.subsection(entry.offset, entry.size)));
    }
    const data = decoded.get(key);
    return data ? { ...entry, data } : entry;
  } catch (error) { reader.warn(`CodeView subsection ${entry.type}, module ${entry.module}: ${String(error)}`); return entry; }
};

export const parseLegacyCodeView = async (
  reader: FileRangeReader, fileSize: number, rvaToOff: RvaToOffset,
  addressOfRawDataRva: number, pointerToRawDataOff: number, dataSize: number,
  addWarning: (message: string) => void
): Promise<PeLegacyCodeViewInfo | null> => {
  const location = getReadableDebugData("Legacy CodeView", fileSize, rvaToOff,
    addressOfRawDataRva, pointerToRawDataOff, dataSize, addWarning);
  if (!location) return null;
  const source = new LegacyCodeViewReader(location.size, (offset, size) => readDebugPayload(reader, rvaToOff,
    addressOfRawDataRva, pointerToRawDataOff, offset, size), addWarning);
  try {
    const header = await source.view(0, 8);
    const signature = String.fromCharCode(...new Uint8Array(header.buffer, header.byteOffset, 4));
    if (!/^NB0[25-9]$|^NB11$/.test(signature)) { addWarning("Unsupported legacy CodeView signature."); return null; }
    const directories: PeLegacyCodeViewInfo["directories"] = [];
    const decoded = new Map<string, LegacyCodeViewData | undefined>();
    const readDirectories = signature === "NB02" ? readCodeViewC6Directories : readLegacyCodeViewDirectories;
    for (const directory of await readDirectories(source, header.getUint32(4, true))) {
      const subsections: PeLegacyCodeViewInfo["directories"][number]["subsections"] = [];
      for (const entry of directory.entries) {
        subsections.push(await decodeSubsection(source, entry, signature, decoded));
      }
      directories.push({ flags: directory.flags, subsections });
    }
    return { signature, directories };
  } catch (error) { addWarning(String(error)); return null; }
};
