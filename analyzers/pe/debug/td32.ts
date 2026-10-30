import type { FileRangeReader } from "../../file-range-reader.js";
import type { RvaToOffset } from "../types.js";
import { getReadableDebugData } from "./data.js";
import { readDebugPayload } from "./payload-reader.js";
import { LegacyCodeViewReader } from "./legacy-codeview-reader.js";
import { readLegacyCodeViewDirectories, type LegacyCodeViewSubsection } from "./legacy-codeview-directory.js";
import { readTd32Names } from "./td32-names.js";
import { readTd32Module } from "./td32-module.js";
import { readTd32ModuleSymbols, readTd32GlobalSymbols } from "./td32-symbols.js";
import { readTd32Source } from "./td32-source.js";
import { readTd32Types } from "./td32-type-records.js";

type Td32Data = Awaited<ReturnType<typeof readTd32Names | typeof readTd32Module |
  typeof readTd32ModuleSymbols | typeof readTd32Source | typeof readTd32Types>>;
export interface PeTd32Info {
  signature: string;
  directories: { flags: number; subsections: (LegacyCodeViewSubsection & { data?: Td32Data })[] }[];
}
const DECODERS: Partial<Record<number, (reader: LegacyCodeViewReader) => Promise<Td32Data>>> = {
  0x130: readTd32Names, 0x120: readTd32Module, 0x124: readTd32ModuleSymbols,
  0x125: readTd32ModuleSymbols, 0x129: readTd32GlobalSymbols, 0x127: readTd32Source,
  0x121: readTd32Types, 0x12b: readTd32Types
};
const isSignature = (value: number): boolean => value === 0x39304246 || value === 0x41304246;

// JCL accepts TD32 at the end of a larger payload, located by the trailer's
// backward displacement. An invalid/missing trailer is warned, never trusted.
const locateTd32 = async (reader: LegacyCodeViewReader): Promise<LegacyCodeViewReader | null> => {
  if (reader.size < 8) return null;
  const footer = await reader.view(reader.size - 8, 8);
  const size = footer.getUint32(4, true);
  if (isSignature(footer.getUint32(0, true)) && size >= 16 && size <= reader.size) {
    const base = reader.subsection(reader.size - size, size);
    if (await base.uint32(0) === footer.getUint32(0, true)) return base;
  }
  if (!isSignature(await reader.uint32(0))) return null;
  reader.warn("TD32 trailer is missing, inconsistent or out of bounds.");
  return reader;
};

const decodeSection = async (reader: LegacyCodeViewReader, entry: LegacyCodeViewSubsection,
  decoded: Map<string, Td32Data | undefined>) => {
  try {
    await reader.view(entry.offset, 0);
    if (entry.size > reader.size - entry.offset) throw new Error("TD32 subsection exceeds payload bounds.");
    const key = `${entry.type}:${entry.offset}:${entry.size}`;
    if (!decoded.has(key)) {
      decoded.set(key, undefined);
      const decode = DECODERS[entry.type];
      if (decode) decoded.set(key, await decode(reader.subsection(entry.offset, entry.size)));
      else reader.warn(`TD32 subsection ${entry.type} has no semantic decoder; its payload is retained in the inventory.`);
    }
    const data = decoded.get(key);
    return data ? { ...entry, data } : entry;
  } catch (error) { reader.warn(`TD32 subsection ${entry.type}: ${String(error)}`); return entry; }
};

const nameIndices = (data: Td32Data | undefined): number[] => {
  if (data?.kind === "module") return [data.nameIndex];
  if (data?.kind === "source") return data.files.map(file => file.nameIndex);
  if (data?.kind === "symbols") return data.records.flatMap(record => [
    ...(record.nameIndex === undefined ? [] : [record.nameIndex]), ...(record.metadata?.nameIndices ?? []),
    ...(record.metadata?.targetNameIndex === undefined ? [] : [record.metadata.targetNameIndex])]);
  if (data?.kind === "types") return data.records.flatMap(record =>
    record.nameIndex === undefined ? [] : [record.nameIndex]);
  return [];
};

const checkNames = (directory: PeTd32Info["directories"][number], warn: (message: string) => void): void => {
  const tables = directory.subsections.flatMap(section => section.data?.kind === "names" ? [section.data.names] : []);
  if (tables.length > 1) warn("TD32 directory contains multiple name tables; name references are ambiguous.");
  const names = tables[0] ?? [];
  for (const { data } of directory.subsections) {
    if (nameIndices(data).some(index => index > names.length)) warn("TD32 name reference is outside the shared name table.");
  }
};

export const parseTd32 = async (
  reader: FileRangeReader, fileSize: number, rvaToOff: RvaToOffset,
  addressOfRawDataRva: number, pointerToRawDataOff: number, dataSize: number,
  addWarning: (message: string) => void
): Promise<PeTd32Info | null> => {
  const location = getReadableDebugData("TD32", fileSize, rvaToOff,
    addressOfRawDataRva, pointerToRawDataOff, dataSize, addWarning);
  if (!location) return null;
  const input = new LegacyCodeViewReader(location.size, (offset, size) => readDebugPayload(reader,
    rvaToOff, addressOfRawDataRva, pointerToRawDataOff, offset, size),
    message => addWarning(message.replaceAll("Legacy CodeView", "TD32").replaceAll("CodeView", "TD32")));
  try {
    const source = await locateTd32(input);
    if (!source) return null;
    const directories: PeTd32Info["directories"] = [];
    const decoded = new Map<string, Td32Data | undefined>();
    for (const directory of await readLegacyCodeViewDirectories(source, await source.uint32(4))) {
      const subsections: PeTd32Info["directories"][number]["subsections"] = [];
      for (const entry of directory.entries) subsections.push(await decodeSection(source, entry, decoded));
      const result = { flags: directory.flags, subsections };
      checkNames(result, source.warn);
      directories.push(result);
    }
    return { signature: await source.uint32(0) === 0x39304246 ? "FB09" : "FB0A", directories };
  } catch (error) { input.warn(String(error)); return null; }
};
