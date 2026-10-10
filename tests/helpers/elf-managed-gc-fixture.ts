import type { ElfUnwindFde } from "../../analyzers/elf/unwind-types.js";
import { relocationFixture } from "../fixtures/elf-relocations.js";
import { managedGcContainerFixture } from "./managed-gc-container-fixture.js";

export const elfManagedGcFrame = (startRva = 32, lsdaRva = 64): ElfUnwindFde => ({
  offset: 0, cieOffset: 0, start: { address: 4096n + BigInt(startRva), indirect: false },
  range: 32n, lsda: { address: 4096n + BigInt(lsdaRva), indirect: false }, instructions: []
});

export const elfManagedGcFixture = () => {
  const source = relocationFixture();
  const managed = managedGcContainerFixture();
  source.elf.nativeAot = managed.metadata;
  source.elf.programHeaders.push({ index: 0, type: 1, typeName: null, offset: 0n, vaddr: 4096n,
    paddr: 4096n, filesz: 1024n, memsz: 1024n, flags: 5, flagNames: [], align: 1n });
  source.bytes.set(managed.gc, 65);
  source.elf.unwind = [{ sectionIndex: 1, cies: [], issues: [], fdes: [elfManagedGcFrame()] }];
  return { ...source, managed };
};
