import type { ElfUnwindFde } from "../../analyzers/elf/unwind-types.js";
import { relocationFixture, relocationStorage } from "../fixtures/elf-relocations.js";
import { managedGcContainerFixture } from "./managed-gc-container-fixture.js";

export const elfManagedGcAddress = (rva: number): bigint =>
  relocationStorage.loadAddress + BigInt(rva);

export const elfManagedGcFrame = (startRva = 32, lsdaRva = 64): ElfUnwindFde => ({
  offset: 0, cieOffset: 0, start: { address: elfManagedGcAddress(startRva), indirect: false },
  range: 32n, lsda: { address: elfManagedGcAddress(lsdaRva), indirect: false }, instructions: []
});

export const elfManagedGcFixture = () => {
  const source = relocationFixture();
  const managed = managedGcContainerFixture();
  source.elf.nativeAot = managed.metadata;
  // PT_LOAD maps one file-sized executable segment; 5 is PF_R|PF_X and alignment 1
  // means no extra file/virtual-address congruence constraint.
  // https://gabi.xinuos.com/elf/07-pheader.html
  source.elf.programHeaders.push({ index: 0, type: 1, typeName: null, offset: 0n,
    vaddr: relocationStorage.loadAddress, paddr: relocationStorage.loadAddress,
    filesz: BigInt(source.bytes.length), memsz: BigInt(source.bytes.length),
    flags: 5, flagNames: [], align: 1n });
  // NativeAOT's LSDA prefix is one byte; GCInfo starts immediately after it.
  source.bytes.set(managed.gc, managed.layout.rootUnwindRva + 1);
  source.elf.unwind = [{ sectionIndex: 1, cies: [], issues: [], fdes: [elfManagedGcFrame()] }];
  return { ...source, managed };
};
