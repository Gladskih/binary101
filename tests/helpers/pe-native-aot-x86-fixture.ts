"use strict";

import { IMAGE_FILE_MACHINE_I386 } from "../../analyzers/coff/machine.js";
import { parseExceptionDirectory } from "../../analyzers/pe/exception/index.js";
import type { PeNativeAotCandidate } from "../../analyzers/pe/native-aot.js";
import { MockFile } from "./mock-file.js";

export { IMAGE_FILE_MACHINE_I386 };
// dotnet/runtime NativeAOT COFF writer emits I386 .pdata rows as three DWORDs.
// https://github.com/dotnet/runtime/blob/main/src/coreclr/tools/aot/ILCompiler.Compiler/Compiler/ObjectWriter/CoffObjectWriter.Aot.cs
export const NATIVE_AOT_X86_RUNTIME_FUNCTION_ENTRY_SIZE = Uint32Array.BYTES_PER_ELEMENT * 3;
// dotnet/runtime win64unwind.h defines TARGET_X86 UNWIND_INFO as ULONG FunctionLength.
// https://github.com/dotnet/runtime/blob/main/src/coreclr/inc/win64unwind.h
export const NATIVE_AOT_X86_UNWIND_INFO_HEADER_SIZE = Uint32Array.BYTES_PER_ELEMENT;

export interface NativeAotX86Fixture {
  beginRvas: number[];
  bytes: Uint8Array;
  directoryRva: number;
  endRvas: number[];
  nativeAotCandidate: PeNativeAotCandidate;
  unwindRvas: number[];
  view: DataView;
}

const alignToUint32 = (value: number): number =>
  value + (Uint32Array.BYTES_PER_ELEMENT - value % Uint32Array.BYTES_PER_ELEMENT) %
    Uint32Array.BYTES_PER_ELEMENT;

const createRvaAllocator = (): {
  allocate: (size: number) => number;
  current: () => number;
} => {
  let nextRva = Uint32Array.BYTES_PER_ELEMENT;
  return {
    allocate: (size: number): number => {
      const rva = nextRva;
      nextRva = alignToUint32(rva + size);
      return rva;
    },
    current: (): number => nextRva
  };
};

export const writeNativeAotX86RuntimeFunction = (
  view: DataView,
  offset: number,
  beginRva: number,
  endRva: number,
  unwindRva: number
): void => {
  view.setUint32(offset, beginRva >>> 0, true);
  view.setUint32(offset + Uint32Array.BYTES_PER_ELEMENT, endRva >>> 0, true);
  view.setUint32(offset + Uint32Array.BYTES_PER_ELEMENT * 2, unwindRva >>> 0, true);
};

export const writeNativeAotX86UnwindInfo = (
  view: DataView,
  offset: number,
  functionLength: number
): void => {
  view.setUint32(offset, functionLength >>> 0, true);
};

export const createNativeAotX86Fixture = (
  functionLengths: number[] = [
    NATIVE_AOT_X86_UNWIND_INFO_HEADER_SIZE,
    NATIVE_AOT_X86_UNWIND_INFO_HEADER_SIZE + NATIVE_AOT_X86_UNWIND_INFO_HEADER_SIZE
  ]
): NativeAotX86Fixture => {
  const allocator = createRvaAllocator();
  const directoryRva = allocator.allocate(
    functionLengths.length * NATIVE_AOT_X86_RUNTIME_FUNCTION_ENTRY_SIZE
  );
  const beginRvas = functionLengths.map(length => allocator.allocate(length));
  const endRvas = beginRvas.map((beginRva, index) => beginRva + functionLengths[index]!);
  const unwindRvas = functionLengths.map(() =>
    allocator.allocate(NATIVE_AOT_X86_UNWIND_INFO_HEADER_SIZE)
  );
  const bytes = new Uint8Array(allocator.current()).fill(0);
  const view = new DataView(bytes.buffer);
  for (const [index, beginRva] of beginRvas.entries()) {
    writeNativeAotX86RuntimeFunction(
      view,
      directoryRva + index * NATIVE_AOT_X86_RUNTIME_FUNCTION_ENTRY_SIZE,
      beginRva,
      endRvas[index]!,
      unwindRvas[index]!
    );
    writeNativeAotX86UnwindInfo(view, unwindRvas[index]!, functionLengths[index]!);
  }
  return {
    beginRvas,
    bytes,
    directoryRva,
    endRvas,
    nativeAotCandidate: {
      status: "candidate",
      evidence: ["Export named DotNetRuntimeDebugHeader is present."],
      note:
        "Native AOT can look like a normal native PE; " +
        "this is conservative local evidence, not a guarantee."
    },
    unwindRvas,
    view
  };
};

export const parseNativeAotX86Fixture = (
  fixture: NativeAotX86Fixture,
  size = fixture.beginRvas.length * NATIVE_AOT_X86_RUNTIME_FUNCTION_ENTRY_SIZE,
  rvaToOff: (rva: number) => number | null = rva => rva
) => parseExceptionDirectory(
  new MockFile(fixture.bytes, "native-aot-x86.bin"),
  [{ name: "EXCEPTION", rva: fixture.directoryRva, size }],
  rvaToOff,
  IMAGE_FILE_MACHINE_I386,
  undefined,
  fixture.nativeAotCandidate
);
