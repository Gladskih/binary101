import { renderOptionChips } from "../../html-utils.js";
import { ELF_MACHINE_OPTIONS } from "../../analyzers/elf/legacy-machine-types.js";
import { ELF_OSABI } from "../../analyzers/elf/constants.js";
import type { ElfOptionEntry } from "../../analyzers/elf/types.js";

export function renderOsAbi(code: number): string {
  if (ELF_OSABI.some(([value]) => value === code)) return renderOptionChips(code, ELF_OSABI);
  // gABI Appendix B reserves 64..255 for e_machine-specific ABI assignments.
  // https://gabi.xinuos.com/elf/b-osabi.html
  return renderOptionChips(code, [...ELF_OSABI, [code,
    code >= 64 ? `Architecture-specific (${code})` : `Unrecognized (${code})`,
    "This value is outside the global OS ABI list; consult the target architecture ABI."
  ]]);
}

export function renderMachine(code: number): string {
  return renderOptionChips(code, [ELF_MACHINE_OPTIONS.find(([value]) => value === code) ??
    [code, `Unknown machine (${code})`, "Unassigned or vendor-specific e_machine value."]]) +
    `<details><summary>Other machine values</summary>` +
    renderOptionChips(code, ELF_MACHINE_OPTIONS.filter(([value]) => value !== code)) + `</details>`;
}

export function renderHeaderOptions(code: number, options: ElfOptionEntry[]): string {
  if (options.some(([value]) => value === code)) return renderOptionChips(code, options);
  return renderOptionChips(code, [...options, [code, `Unknown (${code})`,
    "This numeric code is not in the recognized values for this field."]]);
}
