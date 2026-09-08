import type { ElfHeader, ElfParseResult, ElfSectionHeader } from "../../analyzers/elf/types.js";
import type { ElfRelocationTable } from "../../analyzers/elf/relocation-types.js";

// Synthetic placement, not ABI offsets: disjoint areas let tests replace each payload.
export const relocationStorage = {
  fileSize: 1024, records: 64, symbols: 256, strings: 384, target: 512, dynamic: 768,
  loadAddress: 0x1000n
} as const;

// EI_DATA: https://gabi.xinuos.com/elf/02-eheader.html#elf-identification
const byteOrders = {
  little: { dataByte: 1, dataName: "Little endian" },
  big: { dataByte: 2, dataName: "Big endian" }
} as const;

// SHT_PROGBITS=1; zero defaults, byte alignment. https://gabi.xinuos.com/elf/03-sheader.html
export const relocationSection = (
  index: number, fields: Partial<ElfSectionHeader> = {}
): ElfSectionHeader => ({
  index, nameOff: 0, type: 1, typeName: null, flags: 0n, flagNames: [], addr: 0n,
  offset: 0n, size: 0n, link: 0, info: 0, addralign: 1n, entsize: 0n, ...fields
});

// ET_REL=1. These unit fixtures supply parsed headers, not a complete serialized ELF.
// https://gabi.xinuos.com/elf/02-eheader.html
const relocationHeader = (machine: number, ehsize: number): ElfHeader => ({
  type: 1, typeName: null, machine, machineName: null,
  entry: 0n, phoff: 0n, shoff: 0n, flags: 0, ehsize, phentsize: 0, phnum: 0,
  shentsize: 0, shnum: 0, shstrndx: 0
});

const relocationSections = (symbolEntrySize: number): ElfSectionHeader[] => [
  relocationSection(0, { type: 0 }), // SHT_NULL: reserved section zero (gABI §3).
  relocationSection(1, {
    name: ".debug_info", offset: BigInt(relocationStorage.target), size: 32n
  }), // Small test payload; its size is incidental.
  relocationSection(2, { // SHT_SYMTAB=2: null symbol followed by the target symbol.
    type: 2, offset: BigInt(relocationStorage.symbols), size: BigInt(symbolEntrySize * 2),
    entsize: BigInt(symbolEntrySize), link: 3
  }),
  relocationSection(3, { // SHT_STRTAB=3; "\0target\0" plus a spare NUL byte.
    type: 3, offset: BigInt(relocationStorage.strings), size: 8n
  })
];

const createRelocationStorage = (
  ident: ElfParseResult["ident"], header: ElfHeader, symbolEntrySize: number
) => {
  const bytes = new Uint8Array(relocationStorage.fileSize);
  const view = new DataView(bytes.buffer);
  const elf: ElfParseResult = {
    ident, header, sections: relocationSections(symbolEntrySize), programHeaders: [], issues: [],
    is64: ident.classByte === 2, littleEndian: ident.dataByte === 1, fileSize: bytes.length
  };
  bytes.set(new TextEncoder().encode("\0target\0"), relocationStorage.strings);
  // st_name is the first Elf32_Word in both symbol layouts; 1 skips the leading NUL.
  // https://gabi.xinuos.com/elf/05-symtab.html
  view.setUint32(relocationStorage.symbols + symbolEntrySize, 1, elf.littleEndian);
  return { bytes, view, elf, file: (): File => new File([bytes], "relocations.elf") };
};

const elf32RelocationFixture = (order: keyof typeof byteOrders) => {
  // ELFCLASS32=1, EM_386=3, sizeof(Elf32_Ehdr)=52 (gABI §2).
  // Elf32_Sym: 16 bytes, st_value at +4, st_shndx at +14 (gABI §5).
  const fixture = createRelocationStorage({
    classByte: 1, className: "ELF32", ...byteOrders[order], osabi: 0, abiVersion: 0
  }, relocationHeader(3, 52), 16);
  const symbol = relocationStorage.symbols + 16;
  fixture.view.setUint16(symbol + 14, 1, fixture.elf.littleEndian); // Target section #1.
  fixture.view.setUint32(symbol + 4, 4, fixture.elf.littleEndian); // Offset within target section.
  return { ...fixture, word: (offset: number, value: bigint): void => {
    fixture.view.setUint32(offset, Number(BigInt.asUintN(32, value)), fixture.elf.littleEndian);
  } };
};

const elf64RelocationFixture = (order: keyof typeof byteOrders) => {
  // ELFCLASS64=2, EM_X86_64=62, sizeof(Elf64_Ehdr)=64 (gABI §2).
  // Elf64_Sym: 24 bytes, st_value at +8, st_shndx at +6 (gABI §5).
  const fixture = createRelocationStorage({
    classByte: 2, className: "ELF64", ...byteOrders[order], osabi: 0, abiVersion: 0
  }, relocationHeader(62, 64), 24);
  const symbol = relocationStorage.symbols + 24;
  fixture.view.setUint16(symbol + 6, 1, fixture.elf.littleEndian); // Target section #1.
  fixture.view.setBigUint64(symbol + 8, 4n, fixture.elf.littleEndian); // Offset in target section.
  return { ...fixture, word: (offset: number, value: bigint): void => {
    fixture.view.setBigUint64(offset, BigInt.asUintN(64, value), fixture.elf.littleEndian);
  } };
};

const relocationFactories = { 32: elf32RelocationFixture, 64: elf64RelocationFixture };

export const relocationFixture = (bits: 32 | 64 = 64, order: keyof typeof byteOrders = "little") =>
  relocationFactories[bits](order);

// One Elf64_Rela: https://gabi.xinuos.com/elf/06-reloc.html
// Section indices refer to relocationSections above; #4 is reserved for relocations.
export const relocationTable = (fields: Partial<ElfRelocationTable> = {}): ElfRelocationTable => ({
  offset: relocationStorage.records, size: 24, entrySize: 24, encoding: "RELA", sources: ["test"],
  sectionIndex: 4, symbolTableIndex: 2, targetSectionIndex: 1, ...fields
});
