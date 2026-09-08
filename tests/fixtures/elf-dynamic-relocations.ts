import { relocationFixture, relocationStorage } from "./elf-relocations.js";

// Tag IDs are an independent test oracle, not imported from the analyzer.
// https://gabi.xinuos.com/elf/08-dynamic.html#dynamic-section
const dynamicTags = { RELA: 7, RELASZ: 8, RELAENT: 9, STRTAB: 5, STRSZ: 10, SYMTAB: 6, SYMENT: 11 };

const relocationTags = (wordSize: number, symbolEntrySize: bigint): Map<number, bigint> => new Map([
  [dynamicTags.RELA, relocationStorage.loadAddress + BigInt(relocationStorage.records)],
  // RELA has three class-sized fields: r_offset, r_info, r_addend (gABI §6.1).
  [dynamicTags.RELASZ, BigInt(wordSize * 3)],
  [dynamicTags.RELAENT, BigInt(wordSize * 3)],
  [dynamicTags.STRTAB, relocationStorage.loadAddress + BigInt(relocationStorage.strings)],
  [dynamicTags.STRSZ, 8n], // "\0target\0" plus a spare NUL, as in the section fixture.
  [dynamicTags.SYMTAB, relocationStorage.loadAddress + BigInt(relocationStorage.symbols)],
  [dynamicTags.SYMENT, symbolEntrySize]
]);

const installDynamicTags = (
  fixture: ReturnType<typeof relocationFixture>, tags: Map<number, bigint>, wordSize: number
): void => {
  // Elf32/64_Dyn consists of tag and value, followed by a zero DT_NULL entry.
  // https://gabi.xinuos.com/elf/08-dynamic.html#dynamic-section
  const stride = wordSize * 2;
  fixture.elf.programHeaders.push({ ...fixture.elf.programHeaders[0]!,
    type: 2, index: 1, offset: BigInt(relocationStorage.dynamic), // PT_DYNAMIC (gABI §7).
    filesz: BigInt((tags.size + 1) * stride)
  });
  let position: number = relocationStorage.dynamic;
  for (const [tag, value] of tags) {
    fixture.word(position, BigInt(tag));
    fixture.word(position + wordSize, value);
    position += stride;
  }
  fixture.word(position, 0n);
  fixture.word(position + wordSize, 0n);
};

export const dynamicRelocationFixture = (
  bits: 32 | 64 = 64, order: "little" | "big" = "little"
) => {
  const fixture = relocationFixture(bits, order);
  // ET_DYN=3, PT_LOAD=1, PF_R|PF_W=6; gABI §2 and §7:
  // https://gabi.xinuos.com/elf/07-pheader.html
  fixture.elf.header.type = 3;
  fixture.elf.programHeaders = [{
    type: 1, typeName: null, offset: 0n, vaddr: relocationStorage.loadAddress, paddr: 0n,
    filesz: BigInt(fixture.bytes.length), memsz: BigInt(fixture.bytes.length * 2),
    flags: 6, flagNames: [], align: 8n, index: 0
  }]; // Extra zero-fill space exercises targets without file bytes; 8 aligns both classes.
  const tags = relocationTags(bits / 8, fixture.elf.sections[2]!.entsize);
  return { ...fixture, tags, installTags: (): void => installDynamicTags(fixture, tags, bits / 8) };
};
