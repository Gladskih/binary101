import { MockFile } from "../helpers/mock-file.js";
import { createPeWithSectionAndIat } from "./sample-files-pe.js";

// CE PDATA: 8-bit prolog, 22-bit function instruction count, width and EH flags.
// https://learn.microsoft.com/en-us/previous-versions/windows/embedded/ms940664(v=msdn.10)
export const ceFunctionWord = (instructions = 4, prolog = 1, width = 4, exception = 0): number =>
  (prolog | instructions << 8 | Number(width === 4) << 30 | exception << 31) >>> 0;

export const ceExceptionRows = (rows: readonly (readonly [number, number])[]): MockFile => {
  const bytes = new Uint8Array(rows.length * 8);
  const view = new DataView(bytes.buffer);
  rows.forEach((row, index) => {
    view.setUint32(index * 8, row[0], true);
    view.setUint32(index * 8 + 4, row[1], true);
  });
  return new MockFile(bytes);
};

export const ceExceptionMap = (rva: number): number | null =>
  rva >= 0x1000 && rva < 0x1200 ? rva - 0x1000 : null;

export const ceExceptionImage = (handler = 0x401100, data = 0x401110): MockFile => {
  const bytes = new Uint8Array(512);
  const view = new DataView(bytes.buffer);
  view.setUint32(0x78, handler, true); // PDATA_EH immediately precedes the function at VA 0x401080.
  view.setUint32(0x7c, data, true);
  return new MockFile(bytes);
};

export const createCeExceptionPe = (machine = 0x1c0, word = ceFunctionWord()): MockFile => {
  const bytes = new Uint8Array(1544); // Two aligned raw sections and a separate 8-byte debug copy.
  bytes.set(createPeWithSectionAndIat());
  const view = new DataView(bytes.buffer);
  const optional = view.getUint32(0x3c, true) + 24;
  const section = optional + 224 + 40;
  view.setUint16(optional - 20, machine, true);
  view.setUint16(optional - 18, 2, true);
  view.setUint16(optional + 68, 9, true); // IMAGE_SUBSYSTEM_WINDOWS_CE_GUI.
  view.setUint32(optional + 56, 0x3000, true);
  view.setBigUint64(optional + 96 + 12 * 8, 0n, true);
  view.setUint32(optional + 96 + 3 * 8, 0x2000, true);
  view.setUint32(optional + 96 + 3 * 8 + 4, 8, true);
  view.setUint32(optional + 96 + 6 * 8, 0x1140, true);
  view.setUint32(optional + 96 + 6 * 8 + 4, 28, true);
  bytes.set(new TextEncoder().encode(".pdata"), section);
  view.setUint32(section + 8, 8, true);
  view.setUint32(section + 12, 0x2000, true);
  view.setUint32(section + 16, 512, true);
  view.setUint32(section + 20, 1024, true);
  view.setUint32(section + 36, 0x40000040, true);
  const payload = ceExceptionRows([[0x401080, word]]);
  bytes.set(payload.data, 1024);
  bytes.set(payload.data, 1536);
  view.setUint32(0x278, 0x401100, true);
  view.setUint32(0x27c, 0x401110, true);
  view.setUint32(0x340 + 12, 5, true);
  view.setUint32(0x340 + 16, 8, true);
  view.setUint32(0x340 + 24, 1536, true);
  return new MockFile(bytes);
};
