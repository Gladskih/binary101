import { MockFile } from "../helpers/mock-file.js";
import { createPePlusWithSection, createPeWithSectionAndIat } from "./sample-files-pe.js";

// Microsoft .pdata MIPS / IMAGE_ALPHA[64]_RUNTIME_FUNCTION_ENTRY: five VAs.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-pdata-section
export const riscExceptionRows = (rows: readonly (readonly bigint[])[], width = 4): MockFile => {
  const bytes = new Uint8Array(rows.length * width * 5);
  const view = new DataView(bytes.buffer);
  rows.forEach((row, index) => row.forEach((value, column) => {
    if (width === 8) view.setBigUint64((index * 5 + column) * width, value, true);
    else view.setUint32((index * 5 + column) * width, Number(value), true);
  }));
  return new MockFile(bytes);
};

export const riscExceptionImage = (): MockFile => new MockFile(new Uint8Array(512));
export const riscExceptionMap = (rva: number): number | null =>
  rva >= 0x1000 && rva < 0x1200 ? rva - 0x1000 : null;

export const createNtRiscPe = (machine = 0x166): MockFile => {
  const width = machine === 0x284 ? 8 : 4;
  const template = width === 8 ? createPePlusWithSection() : createPeWithSectionAndIat();
  const bytes = new Uint8Array(template.length + width * 5);
  bytes.set(template);
  const view = new DataView(bytes.buffer);
  const optional = view.getUint32(0x3c, true) + 24;
  const directories = optional + (width === 8 ? 112 : 96);
  const base = width === 8 ? 0x1234567800000000n : 0x400000n;
  if (width === 8) view.setBigUint64(optional + 24, base, true);
  view.setUint16(optional - 20, machine, true);
  view.setBigUint64(directories + 12 * 8, 0n, true); // Clear incidental fixture IAT.
  view.setUint32(directories + 3 * 8, 0x1100, true);
  view.setUint32(directories + 3 * 8 + 4, width * 5, true);
  view.setUint32(directories + 6 * 8, 0x1140, true);
  view.setUint32(directories + 6 * 8 + 4, 28, true);
  const payload = riscExceptionRows([[base + 0x1000n, base + 0x1040n, 0n, 0n, base + 0x1010n]], width);
  bytes.set(payload.data, 0x300);
  bytes.set(payload.data, template.length);
  view.setUint32(0x340 + 12, 5, true); // IMAGE_DEBUG_TYPE_EXCEPTION, raw-only copy.
  view.setUint32(0x340 + 16, payload.size, true);
  view.setUint32(0x340 + 24, template.length, true);
  return new MockFile(bytes);
};

export const createNtRiscSecondaryPe = (type = 3): MockFile => {
  const primary = createNtRiscPe();
  const bytes = new Uint8Array(primary.size + 20);
  bytes.set(primary.data);
  const view = new DataView(bytes.buffer);
  const payload = riscExceptionRows([[0x401000n, 0x401040n, 0n, 0n, 0x401010n],
    [0x401040n, 0x401080n, 0n, BigInt(type), 0x401100n]]);
  view.setUint32(0x58 + 96 + 3 * 8 + 4, payload.size, true);
  view.setUint32(0x340 + 16, payload.size, true);
  bytes.set(payload.data, 0x300);
  bytes.set(payload.data, view.getUint32(0x340 + 24, true));
  return new MockFile(bytes);
};

// Digital Alpha NT section 9.1: secondary ranges name the original procedure.
// GNU peXXigen.c: EM = (handler bit 0 << 2) | prolog bits 0-1.
export const createAlphaRiscPe = (): MockFile => {
  const file = createNtRiscSecondaryPe(0);
  const view = new DataView(file.data.buffer);
  view.setUint16(view.getUint32(0x3c, true) + 4, 0x184, true);
  view.setUint32(0x308, 1, true);
  view.setUint32(0x310, 0x401013, true);
  view.setUint32(0x31c, 0x401100, true);
  view.setUint32(0x320, 0x401110, true);
  view.setUint32(0x324, 0x401000, true);
  file.data.set(file.data.slice(0x300, 0x328), view.getUint32(0x340 + 24, true));
  return new MockFile(file.data);
};

// Controlled rows follow GNU's PowerPC code-significance interpretation, not
// compiler output. The glue row uses dlltool's begin+13 tagged prolog encoding.
export const createPowerPcCodeSignificancePe = (): MockFile => {
  const file = createNtRiscPe(0x1f0);
  const payload = riscExceptionRows([
    [0x401000n, 0x401018n, 0n, 1n, 0x40100dn],
    [0x401020n, 0x401038n, 0n, 2n, 0x40102dn],
    [0x401040n, 0x401058n, 0n, 3n, 0x40104dn]
  ]);
  const bytes = new Uint8Array(file.size + payload.size - 20);
  bytes.set(file.data);
  const view = new DataView(bytes.buffer);
  view.setUint32(0x58 + 96 + 3 * 8 + 4, payload.size, true);
  view.setUint32(0x340 + 16, payload.size, true);
  bytes.set(payload.data, 0x300);
  bytes.set(payload.data, view.getUint32(0x340 + 24, true));
  return new MockFile(bytes);
};
