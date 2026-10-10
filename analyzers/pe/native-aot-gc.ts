import type { FileRangeReader } from "../file-range-reader.js";
import type { NativeAotMetadata } from "../native-aot/format.js";
import type { PeWindowsCore } from "./types.js";
import { readMappedRvaPrefix } from "./rva-byte-reader.js";
import { locateNativeAotGcInfo } from "./exception/amd64/managed-gc-locations.js";
import { PeManagedGcBlobs } from "./exception/amd64/managed-gc-blobs.js";

const readMethod = async (blobs: PeManagedGcBlobs, core: PeWindowsCore,
  startRva: number, unwindRva: number, metadata: NativeAotMetadata): Promise<void> => {
  try {
    const gcRva = await locateNativeAotGcInfo(blobs.reader, core.rvaToOff, unwindRva);
    if (gcRva == null) return;
    const info = await blobs.read(unwindRva, gcRva);
    if (info) metadata.methodGcMaps!.methods.push({ startRva, info });
  } catch (error) {
    blobs.warnings.add(`NativeAOT GC info: ${error instanceof Error ? error.message : String(error)}`);
  }
};

const readMethods = async (reader: FileRangeReader, core: PeWindowsCore,
  metadata: NativeAotMetadata, view: DataView, warnings: Set<string>): Promise<void> => {
  const roots = new Set(metadata.stackTraceMap?.entries.map(entry => entry.methodRva));
  const unwinds = new Set<number>();
  for (let offset = 0; offset + 12 <= view.byteLength; offset += 12) {
    unwinds.add(view.getUint32(offset + 8, true));
  }
  const blobs = new PeManagedGcBlobs(reader, core.rvaToOff, unwinds,
    metadata.majorVersion >= 11 ? 4 : 3, warnings);
  for (let offset = 0; offset + 12 <= view.byteLength; offset += 12) {
    const startRva = view.getUint32(offset, true);
    if (!roots.has(startRva)) continue;
    const unwindRva = view.getUint32(offset + 8, true);
    await readMethod(blobs, core, startRva, unwindRva, metadata);
  }
};

/** Stack-trace identities distinguish managed roots from native C/C++ unwind records. */
export const readPeNativeAotGc = async (reader: FileRangeReader, core: PeWindowsCore,
  metadata: NativeAotMetadata): Promise<void> => {
  if (core.coff.Machine !== 0x8664) return;
  const directory = core.dataDirs[3];
  if (!directory?.rva || !directory.size) return;
  const warnings = new Set<string>();
  metadata.methodGcMaps = { methods: [], warnings: [] };
  try {
    const view = await readMappedRvaPrefix(reader, directory.rva, directory.size, core.rvaToOff);
    if (view.byteLength !== directory.size || view.byteLength % 12) {
      warnings.add("NativeAOT runtime-function table is truncated.");
    }
    await readMethods(reader, core, metadata, view, warnings);
  } catch (error) { warnings.add(`NativeAOT GC info: ${error instanceof Error ? error.message : String(error)}`); }
  metadata.methodGcMaps.warnings.push(...warnings);
};
