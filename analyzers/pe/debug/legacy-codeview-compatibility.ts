import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";

export interface LegacyCodeViewPublics { kind: "publics"; names: string[]; }
export interface LegacyCodeViewFrameMap { kind: "frameMap"; frames: number[]; }
export interface LegacyCodeViewOldLines {
  kind: "oldLines"; files: { name: string; segment: number; lines: { line: number; offset: number }[] }[];
}

// Microsoft Symbol and Type Information (TIS), section 7.4: sstPublic,
// sstSrcLnSeg and sstMPC. PE uses the 32-bit offset variant.
// https://openwatcom.org/ftp/devel/docs/CodeView.pdf
export const readLegacyCodeViewPublics = async (reader: LegacyCodeViewReader): Promise<LegacyCodeViewPublics> => {
  const names: string[] = [];
  let offset = 0;
  while (offset < reader.size) {
    await reader.view(offset, 8);
    const value = await reader.pascal(offset + 8);
    names.push(value.name);
    offset = value.end;
  }
  return { kind: "publics", names };
};

export const readLegacyCodeViewFrameMap = async (reader: LegacyCodeViewReader): Promise<LegacyCodeViewFrameMap> => {
  const count = await reader.uint16(0);
  if (count * 2 > reader.size - 2) throw new Error("CodeView segment-to-frame map is truncated.");
  const frames: number[] = [];
  for (let index = 0; index < count; index++) frames.push(await reader.uint16(2 + index * 2));
  return { kind: "frameMap", frames };
};

export const readLegacyCodeViewOldLines = async (reader: LegacyCodeViewReader): Promise<LegacyCodeViewOldLines> => {
  const files: LegacyCodeViewOldLines["files"] = [];
  let offset = 0;
  while (offset < reader.size) {
    const name = await reader.pascal(offset);
    const header = await reader.view(name.end, 4);
    const count = header.getUint16(2, true);
    if (count * 6 > reader.size - name.end - 4) throw new Error("CodeView source line pairs are truncated.");
    const lines: LegacyCodeViewOldLines["files"][number]["lines"] = [];
    for (let index = 0; index < count; index++) {
      const view = await reader.view(name.end + 4 + index * 6, 6);
      lines.push({ line: view.getUint16(0, true), offset: view.getUint32(2, true) });
    }
    files.push({ name: name.name, segment: header.getUint16(0, true), lines });
    offset = name.end + 4 + count * 6;
  }
  return { kind: "oldLines", files };
};
