import { ELF_FILE_TYPE, ELF_MACHINE_ID, ELF_SEGMENT_TYPE } from "./abi-constants.js";
import type { ElfHeader, ElfIdent, ElfParseResult } from "./types.js";

// Linux can load ELFOSABI_NONE as well as ELFOSABI_GNU. These checks describe
// Linux compatibility for the x86 and AArch64 ABIs, including x32.
// https://gabi.xinuos.com/elf/b-osabi.html
export const elfLinuxLoadProfile = (ident: ElfIdent, header: ElfHeader): "linux" | undefined => {
  if (ident.osabi !== 0 && ident.osabi !== 3) return undefined;
  if (header.type !== ELF_FILE_TYPE.EXEC && header.type !== ELF_FILE_TYPE.DYN) return undefined;
  const { machine } = header;
  return machine === ELF_MACHINE_ID.I386 || machine === ELF_MACHINE_ID.X86_64 ||
    machine === ELF_MACHINE_ID.AARCH64 ? "linux" : undefined;
};

// x86 uses 4 KiB base pages; 4 KiB is the smallest Linux AArch64 granule.
// https://github.com/torvalds/linux/blob/master/arch/x86/include/asm/page_types.h
// https://github.com/torvalds/linux/blob/master/arch/arm64/Kconfig
const minimumPageSize = 4096n;

// Linux load_elf_phdrs and glibc's _dl_map_object_from_fd use fixed-size program
// headers.
// https://github.com/torvalds/linux/blob/master/fs/binfmt_elf.c
// https://github.com/bminor/glibc/blob/master/elf/dl-load.c
export const validateElfLinuxLoadLayout = (image: ElfParseResult): void => {
  if (!elfLinuxLoadProfile(image.ident, image.header)) return;
  const { header, issues } = image;
  const programHeaderSize = image.is64 ? 56 : 32;
  if (header.phnum && header.phentsize > programHeaderSize) {
    issues.push(`Linux requires e_phentsize to be ${programHeaderSize} bytes for this ELF class.`);
  }
  const loads = image.programHeaders.filter(segment => segment.type === ELF_SEGMENT_TYPE.LOAD);
  if (!loads.length && image.programHeaders.length === header.phnum) {
    issues.push("A loadable Linux ELF image requires at least one PT_LOAD segment.");
  }
  const addressLimit = 1n << (image.is64 ? 64n : 32n);
  for (const load of loads) {
    if (load.vaddr + load.memsz > addressLimit) {
      issues.push(`PT_LOAD #${load.index}: the memory range exceeds the ELF address space.`);
    }
    // A valid power-of-two p_align of at least 4 KiB already implies this check.
    if (load.align < minimumPageSize && load.vaddr % minimumPageSize !== load.offset % minimumPageSize) {
      issues.push(`PT_LOAD #${load.index}: p_vaddr and p_offset differ modulo the minimum Linux page size (4096 bytes).`);
    }
  }
};
