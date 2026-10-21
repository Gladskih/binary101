import type { LegacyCodeViewData, PeLegacyCodeViewInfo } from "../../analyzers/pe/debug/legacy-codeview.js";

export const createLegacyCodeViewInfo = (): PeLegacyCodeViewInfo => {
  const data: LegacyCodeViewData[] = [
    { kind: "module", name: "<module>.obj", library: 1, overlay: 0, style: "CV",
      segments: [{ segment: 1, offset: 16, size: 24 }] },
    { kind: "libraries", names: ["", "library.lib"] },
    { kind: "symbols", records: [{ type: 0x203, name: "<public>" }, { type: 6 }, { type: 0x203, name: "second" }] },
    { kind: "types", records: [{ type: 5, name: "Structure", uniqueName: ".?AU<Structure>@@" }, { type: 2 }, { type: 0x204,
      members: [{ type: 0x406, name: "<field>" }, { type: 0x403, name: "first" },
        { type: 0x403, name: "" }, { type: 0x405, continuation: 0x1001 }] }] },
    { kind: "source", files: [{ name: "source.c", segments: [{ segment: 1, start: 16, end: 24,
      lines: [{ offset: 16, line: 7 }, { offset: 20, line: 7 }, { offset: 24, line: 9 }] }] }] },
    { kind: "segmentNames", names: [{ offset: 0, name: ".text" }, { offset: 6, name: "CODE" }] },
    { kind: "segmentMap", logicalCount: 1, segments: [{ flags: 0x10f, overlay: 0, group: 0, frame: 1,
      name: 0, className: 6, offset: 16, size: 24 }] },
    { kind: "files", names: ["source.c", "unreferenced.c"], modules: [{ first: 0, count: 1 }] },
    { kind: "publics", names: ["old_public"] },
    { kind: "oldLines", files: [{ name: "old.c", segment: 1, lines: [{ line: 7, offset: 16 }] }] },
    { kind: "frameMap", frames: [1, 1, 2] }
  ];
  return { signature: "NB09", directories: [{ flags: 0, subsections: data.map((value, index) => ({
    type: 0x120 + index, module: 1, offset: 0, size: 32, data: value })) }] };
};
