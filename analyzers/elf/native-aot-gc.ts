import { createFileRangeReader } from "../file-range-reader.js";
import type { ElfParseResult } from "./types.js";
import type { ElfUnwindFde } from "./unwind-types.js";
import { getElfImageBase } from "./native-aot-image.js";
import { ElfNativeAotGcBlobs } from "./native-aot-gc-blobs.js";
import { identifyNativeAotGcFunclets } from "./native-aot-gc-funclets.js";
import type { NativeAotMethodGcMaps } from "../native-aot/gc-info-types.js";

const managedFrames = (elf: ElfParseResult, imageBase: bigint): ElfUnwindFde[] => {
  const roots = new Set(elf.nativeAot?.stackTraceMap?.entries.flatMap(entry =>
    entry.methodRva == null ? [] : [imageBase + BigInt(entry.methodRva)]));
  return (elf.unwind ?? []).flatMap(section => section.fdes.filter(frame =>
    frame.start && !frame.start.indirect && roots.has(frame.start.address)));
};

const readMethods = async (blobs: ElfNativeAotGcBlobs, frames: ElfUnwindFde[], imageBase: bigint,
  maps: NativeAotMethodGcMaps, nativeLsdas: Set<bigint>): Promise<void> => {
  for (const frame of frames) {
    if (!frame.lsda || frame.lsda.indirect) continue;
    nativeLsdas.add(frame.lsda.address);
    try {
      const info = await blobs.read(frame.lsda.address);
      if (info) maps.methods.push({ startRva: Number(frame.start!.address - imageBase), info });
    } catch (error) { blobs.warnings.add(`NativeAOT GC info: ${error instanceof Error ? error.message : String(error)}`); }
  }
};

export const readElfNativeAotGc = async (file: File, elf: ElfParseResult): Promise<Set<bigint>> => {
  const nativeLsdas = new Set<bigint>();
  const metadata = elf.nativeAot;
  const imageBase = getElfImageBase(elf.programHeaders);
  if (!metadata || imageBase == null || elf.header.machine !== 62 || !elf.littleEndian) return nativeLsdas;
  const warnings = new Set<string>();
  metadata.methodGcMaps = { methods: [], warnings: [] };
  const frames = managedFrames(elf, imageBase);
  const allAddresses = new Set((elf.unwind ?? []).flatMap(section => section.fdes
    .flatMap(frame => frame.lsda && !frame.lsda.indirect ? [frame.lsda.address] : [])));
  const reader = createFileRangeReader(file, 0, file.size);
  const blobs = new ElfNativeAotGcBlobs(reader,
    elf.programHeaders, allAddresses, metadata.majorVersion >= 11 ? 4 : 3, warnings);
  await readMethods(blobs, frames, imageBase, metadata.methodGcMaps, nativeLsdas);
  try { await identifyNativeAotGcFunclets(reader, elf, frames, nativeLsdas); }
  catch (error) { warnings.add(`NativeAOT GC funclets: ${error instanceof Error ? error.message : String(error)}`); }
  metadata.methodGcMaps.warnings.push(...warnings);
  return nativeLsdas;
};
