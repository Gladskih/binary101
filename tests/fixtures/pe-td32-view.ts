import type { PeTd32Info } from "../../analyzers/pe/debug/td32.js";

export const createTd32Info = (): PeTd32Info => ({ signature: "FB09", directories: [{ flags: 0, subsections: [
  { type: 0x130, module: 0, offset: 0, size: 40,
    data: { kind: "names", names: ["<unit>.pas", "Worker", "source.pas", "unused type name"] } },
  { type: 0x120, module: 1, offset: 0, size: 40, data: { kind: "module", overlay: 0, library: 0,
    style: 0x4454, nameIndex: 1, timestamp: 0, segments: [{ segment: 1, flags: 1, offset: 16, size: 24 },
      { segment: 2, flags: 0, offset: 8, size: 8 }] } },
  { type: 0x125, module: 1, offset: 0, size: 40,
    data: { kind: "symbols", records: [{ type: 0x205, nameIndex: 2 }, { type: 6 },
      { type: 1, compiler: "<compiler>" }, { type: 0x7777, nameIndex: 99 }, { type: 0x203, nameIndex: 0 }] } },
  { type: 0x127, module: 1, offset: 0, size: 40, data: { kind: "source", files: [{ nameIndex: 3,
    segments: [{ segment: 1, start: 16, end: 24, lines: [{ offset: 16, line: 7 },
      { offset: 20, line: 7 }, { offset: 24, line: 9 }] }] }] } },
  { type: 0x12b, module: 0, offset: 0, size: 8, data: { kind: "types", version: 1,
    records: [{ index: 0, type: 4, nameIndex: 4 }, { index: 1, type: 4 }, { index: 2, type: 52 }] } },
  { type: 0x999, module: 0, offset: 0, size: 8 }
] }] });
