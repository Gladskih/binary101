import { relocationFixture, relocationSection } from "./elf-relocations.js";
import { DwarfCursor } from "../../analyzers/dwarf/cursor.js";
import { createFileRangeReader } from "../../analyzers/file-range-reader.js";

export const unwindCursor = (bytes: number[], order: "little" | "big" = "little") => {
  const file = new File([new Uint8Array(bytes)], "unwind.bin");
  const issues: string[] = [];
  return { issues, cursor: new DwarfCursor(createFileRangeReader(file, 0, bytes.length),
    { name: ".eh_frame", offset: 0, size: bytes.length, compressed: false },
    0, bytes.length, order === "little", issues) };
};

// LSB 10.6: CIE version 1, zR augmentation, pcrel sdata4 encoding, then one FDE.
// https://refspecs.linuxfoundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/ehframechpt.html
export const elfUnwindFixture = (order: "little" | "big" = "little") => {
  const fixture = relocationFixture(64, order);
  fixture.elf.header.type = 3;
  fixture.elf.sections = [relocationSection(0, { type: 0 }),
    relocationSection(1, { name: ".eh_frame", offset: 64n, size: 48n, addr: 4096n })];
  const little = order === "little";
  fixture.view.setUint32(64, 16, little);
  fixture.view.setUint32(68, 0, little);
  fixture.bytes.set([1, 122, 82, 0, 1, 120, 16, 1, 27, 12, 7, 8], 72);
  fixture.view.setUint32(84, 20, little);
  fixture.view.setUint32(88, 24, little);
  fixture.view.setInt32(92, 4096 - 28, little); // pc = section address + 28 + encoded delta.
  fixture.view.setUint32(96, 32, little);
  fixture.bytes.set([0, 0x41, 0x86, 2, 0, 0, 0, 0], 100);
  return fixture;
};

export const elfSegmentUnwindFixture = (order: "little" | "big" = "little") => {
  const fixture = elfUnwindFixture(order);
  const load = { index: 0, type: 1, typeName: "PT_LOAD", offset: 64n, vaddr: 4096n,
    paddr: 4096n, filesz: 72n, memsz: 72n, flags: 4, flagNames: ["R"], align: 4n };
  fixture.elf.sections = [];
  fixture.elf.programHeaders = [load, { ...load, index: 1, type: 0x6474e550,
    typeName: "GNU_EH_FRAME", offset: 128n, vaddr: 4160n, filesz: 8n, memsz: 8n }];
  // .eh_frame_hdr v1, PC-relative sdata4 .eh_frame pointer, omitted index.
  fixture.bytes.set([1, 0x1b, 0xff, 0xff], 128);
  fixture.view.setInt32(132, 4096 - 4164, order === "little");
  return fixture;
};
