import { createFileRangeReader } from "../../analyzers/file-range-reader.js";
import { inlinePeSectionName } from "../../analyzers/pe/sections/name.js";
import type { PeSection, PeWindowsCore } from "../../analyzers/pe/types.js";
import type { PeBaseRelocationResult } from "../../analyzers/pe/directories/reloc.js";
import {
  createDModuleFixture, createDTestModule, D_TEST_ABI, D_TEST_IO, D_TEST_MEMORY,
  writeDTestPointer
} from "./d-runtime.js";

// Independent PE wire expectations, per Microsoft PE Optional Header, Section Flags,
// and Base Relocation Block: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
export const D_TEST_PE = {
  pe32Magic: 0x10b, pe64Magic: 0x20b,
  dataCharacteristics: 0x4000_0040, codeCharacteristics: 0x6000_0020,
  executableFlag: 0x2000_0000,
  dir64Relocation: 10, highlowRelocation: 3, absoluteRelocation: 0,
  relocationPageBytes: 0x1000, relocationHeaderBytes: 8, relocationEntryBytes: 2,
  // Incidental fixture storage, separate from PE/ABI assertions.
  moduleOffset: 64, codeOffset: 512, fileBytes: 768, tableRva: 0x3000
};

const alignBytes = (size: number, alignment: number): number =>
  Math.ceil(size / alignment) * alignment;

const section = (name: string, address: number, offset: number, size: number,
  characteristics = D_TEST_PE.dataCharacteristics): PeSection => ({
  name: inlinePeSectionName(name), virtualAddress: address, pointerToRawData: offset,
  virtualSize: size, sizeOfRawData: size, characteristics
});

export const createDTableRelocations = (tableSection: PeSection, pointers: bigint[],
  pointerSize: 4 | 8): PeBaseRelocationResult => {
  const pages = new Map<number, Array<{ type: number; offset: number }>>();
  pointers.forEach((address, index) => {
    if (address === 0n) return;
    const rva = tableSection.virtualAddress + index * pointerSize;
    const pageRva = Math.floor(rva / D_TEST_PE.relocationPageBytes) * D_TEST_PE.relocationPageBytes;
    const entries = pages.get(pageRva) ?? [];
    entries.push({
      type: pointerSize === D_TEST_ABI.pointer64Bytes
        ? D_TEST_PE.dir64Relocation : D_TEST_PE.highlowRelocation,
      offset: rva - pageRva
    });
    pages.set(pageRva, entries);
  });
  return { totalEntries: [...pages.values()].reduce((count, entries) => count + entries.length, 0),
    blocks: [...pages].map(([pageRva, entries]) => ({ pageRva,
    size: alignBytes(D_TEST_PE.relocationHeaderBytes + entries.length *
      D_TEST_PE.relocationEntryBytes, Uint32Array.BYTES_PER_ELEMENT),
    count: entries.length, entries })) };
};

export const createPeDRuntimeFixture = (pointerSize: 4 | 8 = D_TEST_ABI.pointer64Bytes) => {
  const bytes = new Uint8Array(D_TEST_PE.fileBytes);
  const view = new DataView(bytes.buffer);
  const module = createDModuleFixture(pointerSize, createDTestModule(),
    bytes.subarray(D_TEST_PE.moduleOffset, D_TEST_PE.moduleOffset + D_TEST_MEMORY.regionBytes));
  const tableSection = section(".minfo", D_TEST_PE.tableRva, 0, 0);
  const dataSection = section(".rdata", Number(module.record.address),
    D_TEST_PE.moduleOffset, module.bytes.length);
  const codeSection = section(".text", Number(D_TEST_MEMORY.codeAddress),
    D_TEST_PE.codeOffset, D_TEST_MEMORY.regionBytes, D_TEST_PE.codeCharacteristics);
  const writeTable = (pointers: bigint[]): void => {
    pointers.forEach((address, index) => writeDTestPointer(view, index * pointerSize, address, pointerSize));
    tableSection.virtualSize = tableSection.sizeOfRawData = pointers.length * pointerSize;
  };
  writeTable([0n, module.record.address, module.record.address]);
  const file = new File([bytes], "d.exe");
  const reader = createFileRangeReader(file, 0, bytes.length);
  reader.read = async (offset, size) => new DataView(bytes.buffer,
    Math.min(offset, bytes.length), Math.min(size, Math.max(0, bytes.length - offset)));
  return { file, bytes, reader, module, tableSection, dataSection, codeSection, writeTable,
    core: { opt: { ImageBase: 0n, Magic: pointerSize === D_TEST_ABI.pointer64Bytes
      ? D_TEST_PE.pe64Magic : D_TEST_PE.pe32Magic }, dataDirs: [],
    sections: [tableSection, dataSection, codeSection] } as unknown as PeWindowsCore };
};

export const createRenamedPeDRuntimeFixture = () => {
  const fixture = createPeDRuntimeFixture();
  fixture.tableSection.name = inlinePeSectionName(".renamed");
  const second = createDModuleFixture(D_TEST_ABI.pointer64Bytes, {
    ...createDTestModule(), address: D_TEST_MEMORY.classAddress, name: "second",
    flags: D_TEST_ABI.flags.name | D_TEST_ABI.flags.standalone,
    callbacks: [], importedModules: [], localClasses: []
  }, fixture.module.bytes.subarray(Number(D_TEST_MEMORY.classAddress - fixture.module.record.address)));
  fixture.writeTable([0n, fixture.module.record.address, second.record.address, second.record.address]);
  return { ...fixture, second, relocations: createDTableRelocations(fixture.tableSection,
    [0n, fixture.module.record.address, second.record.address, second.record.address],
    D_TEST_ABI.pointer64Bytes) };
};

export const createDirectoryBoundaryFixture = (
  position: "inside" | "before" | "after", size: number
) => {
  const fixture = createRenamedPeDRuntimeFixture();
  fixture.core.dataDirs = [{ name: "IAT", size, rva: fixture.tableSection.virtualAddress +
    (position === "before" ? -size : position === "after" ? fixture.tableSection.virtualSize : 0) }];
  return fixture;
};

export const createLargePeDRuntimeFixture = (
  fieldReferences = D_TEST_IO.readWindowBytes / D_TEST_ABI.pointer64Bytes + 1, name = "large"
) => {
  const pointerSize = D_TEST_ABI.pointer64Bytes;
  // Regression: exceed the removed 16-window metadata cap with valid, file-backed records.
  const recordCount = 17;
  const moduleSize = alignBytes(D_TEST_ABI.headerBytes + pointerSize +
    fieldReferences * pointerSize + new TextEncoder().encode(`${name}\0`).length,
  pointerSize);
  const dataOffset = D_TEST_PE.moduleOffset + recordCount * pointerSize;
  const bytes = new Uint8Array(dataOffset + recordCount * moduleSize);
  const view = new DataView(bytes.buffer);
  for (let index = 0; index < recordCount; index += 1) {
    const address = D_TEST_MEMORY.moduleAddress + BigInt(index * moduleSize);
    writeDTestPointer(view, index * pointerSize, address, pointerSize);
    createDModuleFixture(pointerSize, { address, name, index: 0,
      flags: D_TEST_ABI.flags.name | D_TEST_ABI.flags.importedModules,
      callbacks: [], localClasses: [],
      importedModules: Array.from({ length: fieldReferences }, () => address)
    }, bytes.subarray(dataOffset + index * moduleSize, dataOffset + (index + 1) * moduleSize));
  }
  const tableSection = section(".minfo", alignBytes(Number(D_TEST_MEMORY.moduleAddress) +
    recordCount * moduleSize, D_TEST_PE.relocationPageBytes), 0, recordCount * pointerSize);
  const file = new File([bytes], "large.exe");
  return { file, tableSection, recordCount,
    core: { opt: { ImageBase: 0n, Magic: D_TEST_PE.pe64Magic }, dataDirs: [],
      sections: [tableSection, section(".rdata", Number(D_TEST_MEMORY.moduleAddress), dataOffset,
        recordCount * moduleSize)] } as unknown as PeWindowsCore,
    reader: createFileRangeReader(file, 0, bytes.length),
    relocations: createDTableRelocations(tableSection,
      Array.from({ length: recordCount }, (_, index) =>
        D_TEST_MEMORY.moduleAddress + BigInt(index * moduleSize)), pointerSize) };
};

export const createManyDTableCandidatesFixture = () => {
  const fixture = createRenamedPeDRuntimeFixture();
  // Regression: discovery must visit all sections beyond the removed 16-candidate cap.
  fixture.core.sections = Array.from({ length: 17 }, () => ({ ...fixture.tableSection }));
  return fixture;
};

export const createPaddedPeDRuntimeFixture = () => {
  const fixture = createRenamedPeDRuntimeFixture();
  const pointers = Array<bigint>(D_TEST_IO.readWindowBytes / D_TEST_ABI.pointer64Bytes + 1).fill(0n);
  pointers[pointers.length - 2] = fixture.module.record.address;
  pointers[pointers.length - 1] = fixture.second.record.address;
  const bytes = new Uint8Array(fixture.bytes.length + pointers.length * D_TEST_ABI.pointer64Bytes);
  bytes.set(fixture.bytes);
  const view = new DataView(bytes.buffer);
  pointers.forEach((address, index) => writeDTestPointer(view,
    fixture.bytes.length + index * D_TEST_ABI.pointer64Bytes, address, D_TEST_ABI.pointer64Bytes));
  fixture.tableSection.pointerToRawData = fixture.bytes.length;
  fixture.tableSection.virtualSize = fixture.tableSection.sizeOfRawData =
    pointers.length * D_TEST_ABI.pointer64Bytes;
  fixture.tableSection.name = inlinePeSectionName(".minfo");
  const file = new File([bytes], "padded.exe");
  return { file, core: fixture.core, tableSection: fixture.tableSection,
    module: fixture.module, second: fixture.second,
    reader: createFileRangeReader(file, 0, file.size),
    relocations: createDTableRelocations(fixture.tableSection, pointers, D_TEST_ABI.pointer64Bytes) };
};

export const createFragmentedDTableFixture = async () => {
  const fixture = createPaddedPeDRuntimeFixture();
  const blob = fixture.file.slice(fixture.tableSection.pointerToRawData);
  const bytes = new Uint8Array(await blob.arrayBuffer());
  const chunks = [bytes.subarray(0, D_TEST_ABI.pointer64Bytes - 1),
    bytes.subarray(D_TEST_ABI.pointer64Bytes - 1, D_TEST_IO.readWindowBytes),
    bytes.subarray(D_TEST_IO.readWindowBytes, bytes.length - 1), bytes.subarray(bytes.length - 1)];
  let cancelled = false;
  blob.stream = () => new ReadableStream<Uint8Array<ArrayBuffer>>({
    start: controller => {
      chunks.forEach(chunk => controller.enqueue(chunk));
      controller.close();
    },
    cancel: () => { cancelled = true; }
  });
  fixture.file.slice = () => blob;
  return { ...fixture, chunks, wasCancelled: () => cancelled };
};

export const watchDModuleHeaderReads = (fixture: ReturnType<typeof createRenamedPeDRuntimeFixture>) => {
  const offsets = [fixture.dataSection.pointerToRawData, fixture.dataSection.pointerToRawData +
    Number(fixture.second.record.address - fixture.module.record.address)];
  const reads: number[] = [];
  const read = fixture.reader.read;
  fixture.reader.read = async (offset, size) => {
    if (size === D_TEST_ABI.headerBytes && offsets.includes(offset)) reads.push(offset);
    return read(offset, size);
  };
  return reads;
};

export const rebaseDPeFixture = (fixture: ReturnType<typeof createPeDRuntimeFixture>,
  imageBase: bigint): void => {
  fixture.core.opt.ImageBase = imageBase;
  fixture.writeTable([0n, fixture.module.record.address + imageBase,
    fixture.module.record.address + imageBase]);
  fixture.module.record.callbacks.forEach((callback, index) =>
    fixture.module.write.callback(index, callback.address + imageBase));
  fixture.module.record.importedModules.forEach((address, index) =>
    fixture.module.write.importedModule(index, address + imageBase));
  fixture.module.record.localClasses.forEach((address, index) =>
    fixture.module.write.localClass(index, address + imageBase));
};
