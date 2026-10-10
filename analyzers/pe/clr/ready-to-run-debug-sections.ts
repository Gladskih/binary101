import type { FileRangeReader } from "../../file-range-reader.js";
import { readMappedRvaPrefix } from "../rva-byte-reader.js";
import type { RvaToOffset } from "../types.js";
import type { PeClrReadyToRun } from "./ready-to-run-types.js";
import { readyToRunImageSections } from "./ready-to-run-image-sections.js";
import { parseReadyToRunDebug } from "./ready-to-run-debug.js";

export const decodeReadyToRunDebugSections = async (reader: FileRangeReader,
  mapper: RvaToOffset, data: PeClrReadyToRun, machine: number | undefined): Promise<void> => {
  const cache = new Map<string, ReturnType<typeof parseReadyToRunDebug>>();
  const warnings = new Set<string>();
  for (const section of readyToRunImageSections(data)) {
    // readytorun.h: ReadyToRunSectionType::DebugInfo = 105.
    if (section.type !== 105) continue;
    const key = `${section.rva}/${section.size}`;
    try {
      let methods = cache.get(key);
      if (!methods) {
        const view = await readMappedRvaPrefix(reader, section.rva, section.size, mapper);
        if (view.byteLength !== section.size) warnings.add("DebugInfo section is truncated.");
        methods = parseReadyToRunDebug(new Uint8Array(view.buffer, view.byteOffset, view.byteLength),
          data.majorVersion!, machine, warnings);
        cache.set(key, methods);
      }
      section.decoded = { kind: "debug-info", methods };
    } catch (error) {
      warnings.add(`DebugInfo: ${error instanceof Error ? error.message : "section read failed"}`);
    }
  }
  data.issues.push(...warnings);
};
