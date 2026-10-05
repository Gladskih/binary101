import type { PeWindowsParseResult } from "../../analyzers/pe/core/parse-result.js";
import type { PeClrHeader } from "../../analyzers/pe/clr/types.js";
import { inlinePeSectionName } from "../../analyzers/pe/sections/name.js";

export const createReadyToRunSeedFixture = (machine = 0x8664, indices = [1, 0, 1]) => {
  // ReadyToRunReader: AMD64 runtime rows are 12 bytes, other targets use 8 bytes.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.Reflection.ReadyToRun/ReadyToRunReader.cs
  const width = machine === 0x8664 ? 12 : 8;
  const tableRva = 0x100;
  const codeRvas = [0x200, 0x220];
  const bytes = new Uint8Array(0x400);
  const view = new DataView(bytes.buffer);
  codeRvas.forEach((rva, index) => {
    view.setUint32(tableRva + width * index, rva, true);
    // A RET makes each seed an independent, verifiable disassembly root on x86/x64.
    bytes[rva] = 0xc3;
  });
  const pe = {
    coff: { Machine: machine },
    opt: { Magic: 0x20b, ImageBase: 0x140000000n, SizeOfImage: bytes.length,
      AddressOfEntryPoint: 0, SizeOfHeaders: 0 },
    rvaToOff: (rva: number) => rva,
    sections: [{ name: inlinePeSectionName(".text"), virtualAddress: codeRvas[0]!,
      virtualSize: 0x100, sizeOfRawData: 0x100, pointerToRawData: codeRvas[0]!,
      // Microsoft PE format: IMAGE_SCN_MEM_EXECUTE.
      characteristics: 0x20000000 }],
    clr: { readyToRun: { status: "ready-to-run", signature: null, majorVersion: 16,
      minorVersion: 0, flags: 0, sectionCount: 2, issues: [], sections: [
        { type: 102, name: "RuntimeFunctions", rva: tableRva, size: width * codeRvas.length },
        { type: 103, name: "MethodDefEntryPoints", rva: 0, size: 0,
          decoded: { kind: "methods", methods: indices.map((runtimeFunctionIndex, index) =>
            ({ methodRid: index + 1, runtimeFunctionIndex, fixupOffset: null })) } }
      ] } } as unknown as PeClrHeader
  } as PeWindowsParseResult;
  const file = new File([bytes], "r2r-seeds.dll");
  const reader = { size: bytes.length,
    read: async (offset: number, size: number) =>
      new DataView(bytes.buffer, offset, Math.min(size, bytes.length - offset)),
    readBytes: async (offset: number, size: number) => bytes.subarray(offset, offset + size) };
  return { bytes, view, pe, file, reader,
    codeRvas, tableRva, width, issues: [] as string[] };
};
