"use strict";

import { parseExceptionDirectory } from "../../analyzers/pe/exception/index.js";
import type { PeClrReadyToRun } from "../../analyzers/pe/clr/ready-to-run-types.js";
import { MockFile } from "./mock-file.js";

// Microsoft PE format, Machine Types: IMAGE_FILE_MACHINE_I386.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#machine-types
export const IMAGE_FILE_MACHINE_I386 = 0x014c;
// dotnet/runtime ReadyToRun format: x86 RuntimeFunctions are 8-byte records.
// https://github.com/dotnet/runtime/blob/main/src/coreclr/tools/aot/ILCompiler.Reflection.ReadyToRun/ReadyToRunReader.cs
export const R2R_X86_RUNTIME_FUNCTION_ENTRY_SIZE = Uint32Array.BYTES_PER_ELEMENT * 2;
// CoreCLR readytorun.h: READYTORUN_EXCEPTION_LOOKUP_TABLE_ENTRY is two DWORDs.
// https://github.com/dotnet/runtime/blob/main/src/coreclr/inc/readytorun.h
export const R2R_EXCEPTION_LOOKUP_ENTRY_SIZE = Uint32Array.BYTES_PER_ELEMENT * 2;
// CoreCLR readytorun.h: READYTORUN_EXCEPTION_CLAUSE is six DWORDs.
// https://github.com/dotnet/runtime/blob/main/src/coreclr/inc/readytorun.h
export const R2R_EXCEPTION_CLAUSE_SIZE = Uint32Array.BYTES_PER_ELEMENT * 6;

export interface ReadyToRunX86Fixture {
  bytes: Uint8Array;
  catchHandlerRva: number;
  clauseArrayRva: number;
  exceptionInfoRva: number;
  finallyHandlerRva: number;
  methodStartRva: number;
  readyToRun: PeClrReadyToRun;
  runtimeFunctionRva: number;
  secondaryMethodStartRva: number;
  view: DataView;
}

const alignToUint32 = (value: number): number =>
  value + (Uint32Array.BYTES_PER_ELEMENT - value % Uint32Array.BYTES_PER_ELEMENT) %
    Uint32Array.BYTES_PER_ELEMENT;

const createRvaAllocator = (): {
  allocate: (size: number) => number;
  current: () => number;
} => {
  // RVA 0 is the PE "not present" value, so fixtures allocate from the first
  // aligned non-zero RVA; exact fixture RVAs carry no format meaning.
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

export const createReadyToRun = (
  runtimeFunctionRva: number,
  runtimeFunctionSize: number,
  exceptionInfoRva = 0,
  exceptionInfoSize = 0
): PeClrReadyToRun => ({
  status: "ready-to-run",
  // CoreCLR readytorun.h: READYTORUN_SIGNATURE is ASCII "RTR" stored little-endian.
  // https://github.com/dotnet/runtime/blob/main/src/coreclr/inc/readytorun.h
  signature: 0x00525452,
  majorVersion: 0,
  minorVersion: 0,
  flags: 0,
  sectionCount: exceptionInfoSize ? 2 : 1,
  sections: [
    {
      // CoreCLR readytorun.h: ReadyToRunSectionType::RuntimeFunctions.
      // https://github.com/dotnet/runtime/blob/main/src/coreclr/inc/readytorun.h
      type: 102,
      name: "RuntimeFunctions",
      rva: runtimeFunctionRva,
      size: runtimeFunctionSize
    },
    ...(exceptionInfoSize
      ? [{
          // CoreCLR readytorun.h: ReadyToRunSectionType::ExceptionInfo.
          // https://github.com/dotnet/runtime/blob/main/src/coreclr/inc/readytorun.h
          type: 104,
          name: "ExceptionInfo",
          rva: exceptionInfoRva,
          size: exceptionInfoSize
        }]
      : [])
  ],
  issues: []
});

const writeU32 = (view: DataView, offset: number, value: number): void => {
  view.setUint32(offset, value >>> 0, true);
};

export const writeRuntimeFunction = (
  view: DataView,
  offset: number,
  beginRva: number,
  unwindRva: number
): void => {
  writeU32(view, offset, beginRva);
  writeU32(view, offset + Uint32Array.BYTES_PER_ELEMENT, unwindRva);
};

export const writeExceptionLookup = (
  view: DataView,
  offset: number,
  methodStartRva: number,
  exceptionInfoRva: number
): void => {
  writeU32(view, offset, methodStartRva);
  writeU32(view, offset + Uint32Array.BYTES_PER_ELEMENT, exceptionInfoRva);
};

export const writeExceptionClause = (
  view: DataView,
  offset: number,
  flags: number,
  handlerStartPc: number
): void => {
  writeU32(view, offset, flags);
  // The parser uses Flags and HandlerStartPC; the remaining DWORD fields are
  // structurally valid fixture data for READYTORUN_EXCEPTION_CLAUSE.
  writeU32(view, offset + Uint32Array.BYTES_PER_ELEMENT, 1);
  writeU32(view, offset + Uint32Array.BYTES_PER_ELEMENT * 2, 2);
  writeU32(view, offset + Uint32Array.BYTES_PER_ELEMENT * 3, handlerStartPc);
  writeU32(view, offset + Uint32Array.BYTES_PER_ELEMENT * 4, handlerStartPc + 1);
  writeU32(view, offset + Uint32Array.BYTES_PER_ELEMENT * 5, 0);
};

export const createReadyToRunX86Fixture = (): ReadyToRunX86Fixture => {
  const allocator = createRvaAllocator();
  const runtimeFunctionRva = allocator.allocate(R2R_X86_RUNTIME_FUNCTION_ENTRY_SIZE * 2);
  const primaryUnwindRva = allocator.allocate(Uint32Array.BYTES_PER_ELEMENT);
  const secondaryUnwindRva = allocator.allocate(Uint32Array.BYTES_PER_ELEMENT);
  const exceptionInfoRva = allocator.allocate(R2R_EXCEPTION_LOOKUP_ENTRY_SIZE * 2);
  const clauseArrayRva = allocator.allocate(R2R_EXCEPTION_CLAUSE_SIZE * 2);
  const methodStartRva = allocator.allocate(Uint8Array.BYTES_PER_ELEMENT);
  const secondaryMethodStartRva = allocator.allocate(Uint8Array.BYTES_PER_ELEMENT);
  const finallyHandlerRva = allocator.allocate(Uint8Array.BYTES_PER_ELEMENT);
  const bytes = new Uint8Array(allocator.current()).fill(0);
  const view = new DataView(bytes.buffer);
  writeRuntimeFunction(view, runtimeFunctionRva, methodStartRva, primaryUnwindRva);
  writeRuntimeFunction(
    view,
    runtimeFunctionRva + R2R_X86_RUNTIME_FUNCTION_ENTRY_SIZE,
    secondaryMethodStartRva,
    secondaryUnwindRva
  );
  writeExceptionLookup(view, exceptionInfoRva, methodStartRva, clauseArrayRva);
  // CoreCLR ExceptionInfoLookupTableNode emits the final sentinel row with
  // MethodStart = -1 and ExceptionInfo pointing to the end of the EH info block.
  // https://github.com/dotnet/runtime/blob/main/src/coreclr/tools/aot/ILCompiler.ReadyToRun/Compiler/DependencyAnalysis/ReadyToRun/ExceptionInfoLookupTableNode.cs
  writeExceptionLookup(
    view,
    exceptionInfoRva + R2R_EXCEPTION_LOOKUP_ENTRY_SIZE,
    0xffff_ffff,
    clauseArrayRva + R2R_EXCEPTION_CLAUSE_SIZE * 2
  );
  writeExceptionClause(view, clauseArrayRva, 0, secondaryMethodStartRva - methodStartRva);
  // CoreCLR corhdr.h: COR_ILEXCEPTION_CLAUSE_FINALLY.
  // https://github.com/dotnet/runtime/blob/main/src/coreclr/inc/corhdr.h
  writeExceptionClause(
    view,
    clauseArrayRva + R2R_EXCEPTION_CLAUSE_SIZE,
    0x0002,
    finallyHandlerRva - methodStartRva
  );
  return {
    bytes,
    catchHandlerRva: secondaryMethodStartRva,
    clauseArrayRva,
    exceptionInfoRva,
    finallyHandlerRva,
    methodStartRva,
    readyToRun: createReadyToRun(
      runtimeFunctionRva,
      R2R_X86_RUNTIME_FUNCTION_ENTRY_SIZE * 2,
      exceptionInfoRva,
      R2R_EXCEPTION_LOOKUP_ENTRY_SIZE * 2
    ),
    runtimeFunctionRva,
    secondaryMethodStartRva,
    view
  };
};

export const parseReadyToRunX86Fixture = (
  fixture: ReadyToRunX86Fixture,
  readyToRun = fixture.readyToRun,
  rvaToOff: (rva: number) => number | null = rva => rva
) => parseExceptionDirectory(
  new MockFile(fixture.bytes, "r2r-x86.bin"),
  [{
    name: "EXCEPTION",
    rva: fixture.runtimeFunctionRva,
    size: readyToRun.sections[0]!.size
  }],
  rvaToOff,
  IMAGE_FILE_MACHINE_I386,
  readyToRun
);
