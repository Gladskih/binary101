// DWARF 5 Table 7.1 and GNU DebugFission package v2 identifiers.
// https://dwarfstd.org/doc/DWARF5.pdf
// https://raw.githubusercontent.com/llvm/llvm-project/main/llvm/lib/DebugInfo/DWARF/DWARFUnitIndex.cpp
const versionFive: Readonly<Record<number, string>> = {
  1: ".debug_info.dwo", 3: ".debug_abbrev.dwo", 4: ".debug_line.dwo",
  5: ".debug_loclists.dwo", 6: ".debug_str_offsets.dwo", 7: ".debug_macro.dwo", 8: ".debug_rnglists.dwo"
};
const versionTwo: Readonly<Record<number, string>> = {
  1: ".debug_info.dwo", 2: ".debug_types.dwo", 3: ".debug_abbrev.dwo", 4: ".debug_line.dwo",
  5: ".debug_loc.dwo", 6: ".debug_str_offsets.dwo", 7: ".debug_macinfo.dwo", 8: ".debug_macro.dwo"
};

export const dwarfPackageSectionName = (version: 2 | 5, identifier: number): string | null =>
  (version === 5 ? versionFive : versionTwo)[identifier] ?? null;

const splitNames = new Set([...Object.values(versionFive), ...Object.values(versionTwo),
  ".debug_str.dwo", ".debug_ranges.dwo"]);

export const isDwarfSplitSection = (name: string): boolean => splitNames.has(name);
export const dwarfSplitBaseName = (name: string): string => isDwarfSplitSection(name) ? name.slice(0, -4) : name;
