import { createPePlusWithSection } from "./sample-files-pe.js";
import { MockFile } from "../helpers/mock-file.js";

export const createPeReadyToRunSeedFile = (runtimeIndex = 0): MockFile => {
  const bytes = createPePlusWithSection();
  const view = new DataView(bytes.buffer);
  // Base fixture .text: RVA 0x1000, raw offset 0x200. Incidental layout within that section.
  // PE/COFF: PE32+ data directories start at optional header + 112, CLR index = 14.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
  const directories = view.getUint32(0x3c, true) + 4 + 20 + 112;
  view.setUint32(directories + 12 * 8, 0, true);
  view.setUint32(directories + 12 * 8 + 4, 0, true);
  view.setUint32(directories + 14 * 8, 0x1080, true);
  view.setUint32(directories + 14 * 8 + 4, 72, true);
  // ECMA-335 II.25.3.3: COR20 header size 72, runtime version 2.5, native header at +64.
  view.setUint32(0x280, 72, true);
  view.setUint16(0x284, 2, true);
  view.setUint16(0x286, 5, true);
  view.setUint32(0x290, 4, true); // COMIMAGE_FLAGS_IL_LIBRARY for R2R.
  view.setUint32(0x2c0, 0x1100, true);
  view.setUint32(0x2c4, 40, true);
  // readytorun.h: RTR signature, section IDs 102 (RuntimeFunctions), 103 (MethodDefEntryPoints).
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/inc/readytorun.h
  view.setUint32(0x300, 0x00525452, true);
  view.setUint16(0x304, 16, true);
  view.setUint32(0x30c, 2, true);
  view.setUint32(0x310, 102, true);
  view.setUint32(0x314, 0x1140, true);
  view.setUint32(0x318, 12, true);
  view.setUint32(0x31c, 103, true);
  view.setUint32(0x320, 0x1160, true);
  view.setUint32(0x324, 4, true);
  view.setUint32(0x340, 0x1020, true);
  view.setUint32(0x344, 0x1023, true);
  view.setUint32(0x348, 0x1180, true);
  // NativeArray: one element, byte-sized index, sparse leaf zero, encoded entrypoint without fixups.
  // NativeArray.cs and ReadyToRunReader.GetRuntimeFunctionIndexFromOffset, v10.0.0.
  bytes.set([8, 1, 0, runtimeIndex * 4], 0x360);
  bytes[0x380] = 1; // AMD64 UNWIND_INFO version 1, zero unwind codes.
  // Intel SDM: RET at the PE entrypoint; an unreachable SYSCALL + RET at the R2R root.
  bytes[0x200] = 0xc3;
  bytes.set([0x0f, 0x05, 0xc3], 0x220);
  return new MockFile(bytes, "r2r-method-seed.dll");
};
