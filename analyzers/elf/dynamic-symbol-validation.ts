import type { ElfSymbolRecord } from "./binary-layout-types.js";

// gABI 5.3 and 5.6: STN_UNDEF is all zero, locals precede other bindings,
// and sh_info is the index after the last local symbol.
// https://gabi.xinuos.com/elf/05-symtab.html
export const createElfDynsymBindingValidator = (boundary: number | undefined, issues: string[]) => {
  let firstNonlocal: number | undefined;
  let reportedLocal = false;
  return {
    record(index: number, symbol: ElfSymbolRecord): void {
      if (index === 0 && [symbol.nameOffset, symbol.value, symbol.size, symbol.info,
        symbol.other, symbol.sectionIndex].some(Boolean)) {
        issues.push("Dynamic symbol #0 (STN_UNDEF) must have all fields zero.");
      }
      if (symbol.info >> 4) {
        firstNonlocal ??= index;
      } else if (firstNonlocal !== undefined && !reportedLocal) {
        issues.push(`Local dynamic symbol #${index} follows a nonlocal symbol (#${firstNonlocal}).`);
        reportedLocal = true;
      }
    },
    finish(count: number | undefined): void {
      if (count === 0) issues.push(".dynsym is missing symbol #0 (STN_UNDEF).");
      const expected = firstNonlocal ?? count;
      if (boundary === 0 || (boundary !== undefined && expected !== undefined && boundary !== expected)) {
        issues.push(`.dynsym sh_info (${boundary}) disagrees with the local symbol boundary` +
          (expected === undefined ? "." : ` (${expected}).`));
      }
    }
  };
};
