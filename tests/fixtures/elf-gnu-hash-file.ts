"use strict";

import type { ElfProgramHeader } from "../../analyzers/elf/types.js";
import { MockFile } from "../helpers/mock-file.js";

const DT_NULL = 0;
const DT_STRTAB = 5;
const DT_SYMTAB = 6;
const DT_STRSZ = 10;
const DT_SYMENT = 11;
const DT_GNU_HASH = 0x6ffffef5;

const PT_LOAD = 1;
const PT_DYNAMIC = 2;

const writeDyn64 = (dv: DataView, index: number, tag: number, value: bigint): void => {
  const base = index * 16;
  dv.setBigInt64(base, BigInt(tag), true);
  dv.setBigUint64(base + 8, value, true);
};

const makeProgramHeader = (partial: Partial<ElfProgramHeader>): ElfProgramHeader =>
  ({
    type: PT_LOAD,
    typeName: partial.type === PT_DYNAMIC ? "PT_DYNAMIC" : "PT_LOAD",
    offset: 0n,
    vaddr: 0n,
    paddr: 0n,
    filesz: 0n,
    memsz: 0n,
    flags: 0,
    flagNames: [],
    align: 0n,
    index: 0,
    ...partial
  }) as ElfProgramHeader;

export type ElfGnuHashDynamicFixture = {
  file: MockFile;
  programHeaders: ElfProgramHeader[];
  symbolName: string;
  symbolVaddr: bigint;
};

export const createElfGnuHashDynamicFixture = (): ElfGnuHashDynamicFixture => {
  const totalSize = 0x180;
  const loadOffset = 0x40;
  const loadVaddr = 0x3040n;
  const strtabOffset = 0x40;
  const gnuHashOffset = 0x80;
  const symtabOffset = 0xc0;
  const dynamicOffset = 0x120;
  const dynamicSize = 0x60;

  const symbolName = "gnu_hash_func";
  const symbolVaddr = 0x401000n;
  const strtabText = `\0${symbolName}\0`;
  const strtabBytes = new TextEncoder().encode(strtabText);

  const bytes = new Uint8Array(totalSize).fill(0);
  bytes.set(strtabBytes, strtabOffset);

  const gnuHash = new DataView(bytes.buffer, gnuHashOffset, 0x20);
  gnuHash.setUint32(0x00, 1, true); // nbuckets
  gnuHash.setUint32(0x04, 1, true); // symoffset
  gnuHash.setUint32(0x08, 1, true); // bloom_size
  gnuHash.setUint32(0x0c, 0, true); // bloom_shift
  gnuHash.setBigUint64(0x10, 0n, true); // bloom[0]
  gnuHash.setUint32(0x18, 1, true); // buckets[0] -> symbol #1
  gnuHash.setUint32(0x1c, 1, true); // chains[0] with end-of-chain bit set

  const symtab = new DataView(bytes.buffer, symtabOffset, 0x30);
  symtab.setUint32(0x18, 1, true); // st_name -> symbolName
  symtab.setUint8(0x1c, 0x12); // STB_GLOBAL | STT_FUNC
  symtab.setUint16(0x1e, 1, true); // defined
  symtab.setBigUint64(0x20, symbolVaddr, true); // st_value

  const dynamic = new DataView(bytes.buffer, dynamicOffset, dynamicSize);
  writeDyn64(dynamic, 0, DT_STRTAB, loadVaddr + BigInt(strtabOffset - loadOffset));
  writeDyn64(dynamic, 1, DT_STRSZ, BigInt(strtabBytes.length));
  writeDyn64(dynamic, 2, DT_SYMTAB, loadVaddr + BigInt(symtabOffset - loadOffset));
  writeDyn64(dynamic, 3, DT_SYMENT, 24n);
  writeDyn64(dynamic, 4, DT_GNU_HASH, loadVaddr + BigInt(gnuHashOffset - loadOffset));
  writeDyn64(dynamic, 5, DT_NULL, 0n);

  return {
    file: new MockFile(bytes, "gnu-hash-dynamic.bin", "application/x-elf"),
    programHeaders: [
      makeProgramHeader({
        index: 0,
        type: PT_LOAD,
        offset: BigInt(loadOffset),
        vaddr: loadVaddr,
        paddr: loadVaddr,
        filesz: BigInt(totalSize - loadOffset),
        memsz: BigInt(totalSize - loadOffset),
        align: 8n
      }),
      makeProgramHeader({
        index: 1,
        type: PT_DYNAMIC,
        offset: BigInt(dynamicOffset),
        vaddr: 0x5000n,
        paddr: 0x5000n,
        filesz: BigInt(dynamicSize),
        memsz: BigInt(dynamicSize),
        align: 8n
      })
    ],
    symbolName,
    symbolVaddr
  };
};
