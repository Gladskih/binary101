import { createPeReadyToRunSeedFile } from "./pe-ready-to-run-seed-file.js";
import { MockFile } from "../helpers/mock-file.js";

export const createPeReadyToRunThunkFile = (): MockFile => {
  const bytes = new Uint8Array(createPeReadyToRunSeedFile().data);
  const view = new DataView(bytes.buffer);
  // READYTORUN_HEADER: directory count at +12; section 106 identifies the import thunk range.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/inc/readytorun.h
  view.setUint32(0x2c4, 52, true);
  view.setUint32(0x30c, 3, true);
  view.setUint32(0x328, 106, true);
  view.setUint32(0x32c, 0x1040, true);
  view.setUint32(0x330, 6, true);
  // ImportThunk: JMP [RIP+0x1a] from 0x1040 targets a data cell at RVA 0x1060.
  bytes.set([0xff, 0x25, 0x1a, 0, 0, 0], 0x240);
  return new MockFile(bytes, "r2r-thunk-seed.dll");
};

export const createPeExportedReadyToRunFile = (): MockFile => {
  const bytes = new Uint8Array(createPeReadyToRunThunkFile().data);
  const view = new DataView(bytes.buffer);
  // PE32+ export directory (index 0), IMAGE_EXPORT_DIRECTORY and its three indexed tables.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#export-directory-table
  const directories = view.getUint32(0x3c, true) + 4 + 20 + 112;
  view.setUint32(directories, 0x11a0, true);
  view.setUint32(directories + 4, 0x60, true);
  view.setUint32(0x3b0, 1, true);
  view.setUint32(0x3b4, 1, true);
  view.setUint32(0x3b8, 1, true);
  view.setUint32(0x3bc, 0x11c8, true);
  view.setUint32(0x3c0, 0x11cc, true);
  view.setUint32(0x3c4, 0x11d0, true);
  view.setUint32(0x3c8, 0x1100, true);
  view.setUint32(0x3cc, 0x11d2, true);
  bytes.set(new TextEncoder().encode("RTR_HEADER\0"), 0x3d2);
  view.setUint32(0x2c0, 0, true);
  view.setUint32(0x2c4, 0, true);
  return new MockFile(bytes, "r2r-exported-header.dll");
};

export const createPeClrFreeReadyToRunFile = (): MockFile => {
  const bytes = new Uint8Array(createPeExportedReadyToRunFile().data);
  const view = new DataView(bytes.buffer);
  const directories = view.getUint32(0x3c, true) + 4 + 20 + 112;
  view.setUint32(directories + 14 * 8, 0, true);
  view.setUint32(directories + 14 * 8 + 4, 0, true);
  return new MockFile(bytes, "r2r-clr-free-header.dll");
};
