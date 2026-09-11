import { DwarfCursor } from "../../analyzers/dwarf/cursor.js";
import { createFileRangeReader } from "../../analyzers/file-range-reader.js";
import type { ElfLsda } from "../../analyzers/elf/lsda-types.js";

export const lsdaFixture = (bytes: number[]) => {
  const file = new File([new Uint8Array(bytes)], "lsda");
  const reader = createFileRangeReader(file, 0, file.size);
  const result: ElfLsda = { address: 4096n, landingPadBase: null, typeEncoding: 255,
    callSiteEncoding: 1, callSites: [], actions: [], types: [], specifications: [], issues: [] };
  const cursorAt = (position: number, end = file.size) => new DwarfCursor(reader,
    { name: "LSDA", offset: 0, size: file.size, compressed: false },
    position, Math.min(end, file.size), true, result.issues);
  return { result, cursorAt };
};
