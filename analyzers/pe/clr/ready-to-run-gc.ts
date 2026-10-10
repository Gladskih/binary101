import type { FileRangeReader } from "../../file-range-reader.js";
import type { RvaToOffset } from "../types.js";
import { readMappedRvaPrefix } from "../rva-byte-reader.js";
import { getCanonicalPeMachine } from "../machine.js";
import { locateReadyToRunGcInfo } from "../exception/amd64/managed-gc-locations.js";
import { PeManagedGcBlobs } from "../exception/amd64/managed-gc-blobs.js";
import type { PeClrReadyToRun } from "./ready-to-run-types.js";
import { readyToRunImageSections } from "./ready-to-run-image-sections.js";
import type { ManagedGcInfo } from "../../native-aot/gc-info-types.js";

export interface ReadyToRunGcMethod { runtimeFunctionIndex: number; startRva: number; info: ManagedGcInfo }

const roots = (data: PeClrReadyToRun): Set<number> => new Set(readyToRunImageSections(data)
  .flatMap(section => section.decoded?.kind === "methods" || section.decoded?.kind === "instance-methods"
    ? section.decoded.methods.map(method => method.runtimeFunctionIndex) : []));

const readMethods = async (reader: FileRangeReader, mapper: RvaToOffset, view: DataView,
  data: PeClrReadyToRun, warnings: Set<string>): Promise<ReadyToRunGcMethod[]> => {
  const unwindRvas = new Set<number>();
  for (let offset = 0; offset + 12 <= view.byteLength; offset += 12) {
    unwindRvas.add(view.getUint32(offset + 8, true));
  }
  // GCInfoToken::ReadyToRunVersionToGcInfoVersion, shared by NativeAOT/runtime.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/inc/gcinfo.h
  const blobs = new PeManagedGcBlobs(reader, mapper, unwindRvas, data.majorVersion! >= 11 ? 4 : 3, warnings);
  const methods: ReadyToRunGcMethod[] = [];
  for (const runtimeFunctionIndex of roots(data)) {
    if (runtimeFunctionIndex * 12 + 12 > view.byteLength) {
      warnings.add("ReadyToRun GC method root is outside the runtime-function table.");
      continue;
    }
    const startRva = view.getUint32(runtimeFunctionIndex * 12, true);
    const unwindRva = view.getUint32(runtimeFunctionIndex * 12 + 8, true);
    try {
      const info = await blobs.read(unwindRva, await locateReadyToRunGcInfo(reader, mapper, unwindRva));
      if (info) methods.push({ runtimeFunctionIndex, startRva, info });
    } catch (error) { warnings.add(`ReadyToRun GC info: ${error instanceof Error ? error.message : String(error)}`); }
  }
  return methods;
};

export const decodeReadyToRunGc = async (reader: FileRangeReader, mapper: RvaToOffset,
  data: PeClrReadyToRun, machine: number | undefined): Promise<void> => {
  if (machine === undefined || getCanonicalPeMachine(machine) !== 0x8664) return;
  const section = data.sections.find(section => section.type === 102);
  if (!section) return;
  const warnings = new Set<string>();
  try {
    const view = await readMappedRvaPrefix(reader, section.rva, section.size, mapper);
    if (view.byteLength !== section.size || view.byteLength % 12) {
      warnings.add("RuntimeFunctions GC table is truncated.");
    }
    section.decoded = { kind: "gc-methods", methods: await readMethods(reader, mapper, view, data, warnings) };
  } catch (error) { warnings.add(`ReadyToRun GC info: ${error instanceof Error ? error.message : String(error)}`); }
  data.issues.push(...warnings);
};
