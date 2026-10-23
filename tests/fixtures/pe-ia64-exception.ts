import { MockFile } from "../helpers/mock-file.js";
import { createPePlusWithSection } from "./sample-files-pe.js";

// Windows SDK IMAGE_IA64_RUNTIME_FUNCTION_ENTRY: three DWORD RVAs, also in PE32+.
export const ia64ExceptionRows = (rows: readonly (readonly [number, number, number])[]): MockFile => {
  const bytes = new Uint8Array(rows.length * 12);
  const view = new DataView(bytes.buffer);
  rows.forEach((row, index) => row.forEach((value, column) => {
    view.setUint32(index * 12 + column * 4, value, true);
  }));
  return new MockFile(bytes);
};

export const ia64ExceptionMap = (rva: number): number | null =>
  rva >= 0x1000 && rva < 0x1200 ? rva - 0x1000 : null;

export const createIa64ExceptionPe = (): MockFile => {
  const template = createPePlusWithSection();
  const payload = ia64ExceptionRows([[0x1000, 0x1040, 0x1180], [0x1040, 0x1080, 0x1180]]);
  const bytes = new Uint8Array(template.length + payload.size);
  bytes.set(template);
  const view = new DataView(bytes.buffer);
  const optional = view.getUint32(0x3c, true) + 24;
  const directories = optional + 112;
  view.setUint16(optional - 20, 0x200, true); // IMAGE_FILE_MACHINE_IA64.
  view.setBigUint64(optional + 24, 0x1234567800000000n, true);
  view.setBigUint64(directories + 12 * 8, 0n, true);
  view.setUint32(directories + 3 * 8, 0x1100, true);
  view.setUint32(directories + 3 * 8 + 4, payload.size, true);
  view.setUint32(directories + 6 * 8, 0x1140, true);
  view.setUint32(directories + 6 * 8 + 4, 28, true);
  bytes.set(payload.data, 0x300);
  bytes.set(payload.data, template.length);
  view.setUint32(0x340 + 12, 5, true); // IMAGE_DEBUG_TYPE_EXCEPTION, raw-only copy.
  view.setUint32(0x340 + 16, payload.size, true);
  view.setUint32(0x340 + 24, template.length, true);
  return new MockFile(bytes);
};
