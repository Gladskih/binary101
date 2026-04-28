"use strict";

import type { FileRangeReader } from "../../analyzers/file-range-reader.js";
import { parseExceptionDirectory } from "../../analyzers/pe/exception/index.js";
import { MockFile } from "./mock-file.js";

// Microsoft PE format, ".pdata": AMD64 RUNTIME_FUNCTION is three 32-bit RVAs.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-pdata-section
export const RUNTIME_FUNCTION_ENTRY_SIZE_BYTES = Uint32Array.BYTES_PER_ELEMENT * 3;
// Microsoft x64 exception handling: UNWIND_INFO begins with a 4-byte fixed header.
// https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64
export const UNWIND_INFO_HEADER_SIZE_BYTES = Uint32Array.BYTES_PER_ELEMENT;
// Microsoft x64 exception handling: each UNWIND_CODE slot is a 2-byte union.
// https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64
export const UNWIND_CODE_SLOT_SIZE_BYTES = Uint16Array.BYTES_PER_ELEMENT;
// Microsoft Learn documents version 1 as the public baseline; LLVM documents version 2
// for MSVC-compatible /d2epilogunwind data.
// https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64
// https://github.com/llvm/llvm-project/pull/129142
export const AMD64_UNWIND_INFO_VERSION_1 = 1;
export const AMD64_UNWIND_INFO_VERSION_2 = 2;
// Microsoft x64 exception handling documents these public UNWIND_INFO flag bits.
// https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64
export const UNW_FLAG_EHANDLER = 0x01;
export const UNW_FLAG_CHAININFO = 0x04;
// LLVM Win64 EH documents UOP_Epilog as opcode 6 in AMD64 UNWIND_INFO v2.
// https://github.com/llvm/llvm-project/commit/22011644
const UOP_EPILOG = 6;
// Microsoft x64 exception handling documents UWOP_ALLOC_SMALL as opcode 2; it is
// useful here only as a regular, non-epilog unwind operation.
// https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64
const UWOP_ALLOC_SMALL = 2;

export interface Amd64ExceptionFixture {
  bytes: Uint8Array;
  directoryRva: number;
  functionBeginRva: number;
  functionEndRva: number;
  primaryUnwindCodeCount: number;
  primaryUnwindRva: number;
  view: DataView;
}

export interface Amd64ExceptionFixtureConfig {
  flags?: number;
  trailingBytes?: number;
  version?: number;
}

interface UnwindSlotParts {
  codeOffset: number;
  operationCode: number;
  operationInfo?: number;
}

export class ShortReadMockFile extends MockFile implements FileRangeReader {
  readonly #shortReadOffset: number;

  constructor(bytes: Uint8Array, fileName: string, shortReadOffset: number) {
    super(bytes, fileName);
    this.#shortReadOffset = shortReadOffset;
  }

  override async read(offset: number, length: number): Promise<DataView> {
    const view = await super.read(offset, length);
    if (offset === this.#shortReadOffset && length > Uint8Array.BYTES_PER_ELEMENT) {
      return new DataView(view.buffer, view.byteOffset, length - Uint8Array.BYTES_PER_ELEMENT);
    }
    return view;
  }
}

const alignToUint32 = (value: number): number =>
  value + (Uint32Array.BYTES_PER_ELEMENT - value % Uint32Array.BYTES_PER_ELEMENT) %
    Uint32Array.BYTES_PER_ELEMENT;

export const createRvaAllocator = (): {
  allocate: (size: number) => number;
  current: () => number;
} => {
  // RVA 0 means "not present" in PE directories and unwind references, so fixtures
  // allocate from the first aligned non-zero RVA.
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

const makeUnwindSlot = ({
  codeOffset,
  operationCode,
  operationInfo = 0
}: UnwindSlotParts): readonly [number, number] =>
  [codeOffset, (operationInfo << 4) | operationCode] as const;

export const epilogScopeSlot = (codeOffset = 1, operationInfo = 1): readonly [number, number] =>
  makeUnwindSlot({ codeOffset, operationCode: UOP_EPILOG, operationInfo });

export const epilogPaddingSlot = (): readonly [number, number] =>
  makeUnwindSlot({ codeOffset: 0, operationCode: UOP_EPILOG });

export const regularUnwindSlot = (codeOffset = 1): readonly [number, number] =>
  makeUnwindSlot({ codeOffset, operationCode: UWOP_ALLOC_SMALL });

export const writeRuntimeFunction = (
  view: DataView,
  offset: number,
  beginRva: number,
  endRva: number,
  unwindInfoRva: number
): void => {
  view.setUint32(offset, beginRva, true);
  view.setUint32(offset + Uint32Array.BYTES_PER_ELEMENT, endRva, true);
  view.setUint32(offset + Uint32Array.BYTES_PER_ELEMENT * 2, unwindInfoRva, true);
};

export const writeUnwindHeader = (
  bytes: Uint8Array,
  unwindInfoRva: number,
  version: number,
  countOfCodes: number,
  flags = 0
): void => {
  bytes[unwindInfoRva] = (flags << 3) | version;
  bytes[unwindInfoRva + Uint8Array.BYTES_PER_ELEMENT * 2] = countOfCodes;
};

export const writeUnwindSlot = (
  bytes: Uint8Array,
  unwindInfoRva: number,
  slotIndex: number,
  slotBytes: readonly [number, number]
): void => {
  const slotOffset = unwindInfoRva + UNWIND_INFO_HEADER_SIZE_BYTES +
    slotIndex * UNWIND_CODE_SLOT_SIZE_BYTES;
  bytes[slotOffset] = slotBytes[0];
  bytes[slotOffset + Uint8Array.BYTES_PER_ELEMENT] = slotBytes[1];
};

export const writeUnwindSlots = (
  bytes: Uint8Array,
  unwindInfoRva: number,
  slots: readonly (readonly [number, number])[]
): void => {
  for (const [slotIndex, slotBytes] of slots.entries()) {
    writeUnwindSlot(bytes, unwindInfoRva, slotIndex, slotBytes);
  }
};

export const writePrimaryUnwindSlots = (
  fixture: Amd64ExceptionFixture,
  slots: readonly (readonly [number, number])[]
): void => writeUnwindSlots(fixture.bytes, fixture.primaryUnwindRva, slots);

export const writePrimaryUnwindHeader = (
  fixture: Amd64ExceptionFixture,
  version: number,
  countOfCodes: number,
  flags = 0
): void => writeUnwindHeader(
  fixture.bytes,
  fixture.primaryUnwindRva,
  version,
  countOfCodes,
  flags
);

export const unwindTailOffset = (unwindInfoRva: number, countOfCodes: number): number =>
  unwindInfoRva + alignToUint32(
    UNWIND_INFO_HEADER_SIZE_BYTES + countOfCodes * UNWIND_CODE_SLOT_SIZE_BYTES
  );

export const primaryUnwindCodeOffset = (fixture: Amd64ExceptionFixture): number =>
  fixture.primaryUnwindRva + UNWIND_INFO_HEADER_SIZE_BYTES;

export const writePrimaryHandlerRva = (
  fixture: Amd64ExceptionFixture,
  handlerRva: number
): void => fixture.view.setUint32(
  unwindTailOffset(fixture.primaryUnwindRva, fixture.primaryUnwindCodeCount),
  handlerRva,
  true
);

export const createAmd64ExceptionFixture = (
  countOfCodes: number,
  trailingBytes = 0,
  version = AMD64_UNWIND_INFO_VERSION_2,
  flags = 0
): Amd64ExceptionFixture => {
  const allocator = createRvaAllocator();
  const directoryRva = allocator.allocate(RUNTIME_FUNCTION_ENTRY_SIZE_BYTES);
  const functionBeginRva = allocator.allocate(Uint8Array.BYTES_PER_ELEMENT);
  const primaryUnwindRva = allocator.allocate(
    UNWIND_INFO_HEADER_SIZE_BYTES + countOfCodes * UNWIND_CODE_SLOT_SIZE_BYTES + trailingBytes
  );
  const bytes = new Uint8Array(allocator.current()).fill(0);
  const view = new DataView(bytes.buffer);
  writeRuntimeFunction(
    view,
    directoryRva,
    functionBeginRva,
    functionBeginRva + Uint8Array.BYTES_PER_ELEMENT,
    primaryUnwindRva
  );
  writeUnwindHeader(bytes, primaryUnwindRva, version, countOfCodes, flags);
  return {
    bytes,
    directoryRva,
    functionBeginRva,
    functionEndRva: functionBeginRva + Uint8Array.BYTES_PER_ELEMENT,
    primaryUnwindCodeCount: countOfCodes,
    primaryUnwindRva,
    view
  };
};

export const createAmd64ExceptionFixtureWithSlots = (
  slots: readonly (readonly [number, number])[],
  config: Amd64ExceptionFixtureConfig = {}
): Amd64ExceptionFixture => {
  const fixture = createAmd64ExceptionFixture(
    slots.length,
    config.trailingBytes ?? 0,
    config.version ?? AMD64_UNWIND_INFO_VERSION_2,
    config.flags ?? 0
  );
  writePrimaryUnwindSlots(fixture, slots);
  return fixture;
};

const paddedUnwindSlotCapacity = (slotCount: number): number =>
  (
    alignToUint32(UNWIND_INFO_HEADER_SIZE_BYTES + slotCount * UNWIND_CODE_SLOT_SIZE_BYTES) -
    UNWIND_INFO_HEADER_SIZE_BYTES
  ) / UNWIND_CODE_SLOT_SIZE_BYTES;

export const createTruncatedUnwindCodeArrayFixture = (): Amd64ExceptionFixture => {
  const slots = [epilogScopeSlot()] as const;
  const fixture = createAmd64ExceptionFixtureWithSlots(slots);
  writePrimaryUnwindHeader(
    fixture,
    AMD64_UNWIND_INFO_VERSION_2,
    paddedUnwindSlotCapacity(slots.length) + 1
  );
  return fixture;
};

export const createChainedAmd64ExceptionFixture = (
  chainedSlots: readonly (readonly [number, number])[]
): Amd64ExceptionFixture => {
  const allocator = createRvaAllocator();
  const directoryRva = allocator.allocate(RUNTIME_FUNCTION_ENTRY_SIZE_BYTES);
  const functionBeginRva = allocator.allocate(Uint8Array.BYTES_PER_ELEMENT);
  const primaryUnwindRva = allocator.allocate(
    UNWIND_INFO_HEADER_SIZE_BYTES + RUNTIME_FUNCTION_ENTRY_SIZE_BYTES
  );
  const chainedUnwindRva = allocator.allocate(
    UNWIND_INFO_HEADER_SIZE_BYTES + chainedSlots.length * UNWIND_CODE_SLOT_SIZE_BYTES
  );
  const bytes = new Uint8Array(allocator.current()).fill(0);
  const view = new DataView(bytes.buffer);
  writeRuntimeFunction(
    view,
    directoryRva,
    functionBeginRva,
    functionBeginRva + Uint8Array.BYTES_PER_ELEMENT,
    primaryUnwindRva
  );
  writeUnwindHeader(bytes, primaryUnwindRva, AMD64_UNWIND_INFO_VERSION_2, 0, UNW_FLAG_CHAININFO);
  writeRuntimeFunction(
    view,
    unwindTailOffset(primaryUnwindRva, 0),
    functionBeginRva,
    functionBeginRva + Uint8Array.BYTES_PER_ELEMENT,
    chainedUnwindRva
  );
  writeUnwindHeader(bytes, chainedUnwindRva, AMD64_UNWIND_INFO_VERSION_2, chainedSlots.length);
  writeUnwindSlots(bytes, chainedUnwindRva, chainedSlots);
  return {
    bytes,
    directoryRva,
    functionBeginRva,
    functionEndRva: functionBeginRva + Uint8Array.BYTES_PER_ELEMENT,
    primaryUnwindCodeCount: 0,
    primaryUnwindRva,
    view
  };
};

export const parseAmd64ExceptionFixture = (
  fixture: Amd64ExceptionFixture,
  file: File & FileRangeReader = new MockFile(fixture.bytes, "exception-unwind-v2.bin")
) => parseExceptionDirectory(
  file,
  [{ name: "EXCEPTION", rva: fixture.directoryRva, size: RUNTIME_FUNCTION_ENTRY_SIZE_BYTES }],
  rva => rva
);
