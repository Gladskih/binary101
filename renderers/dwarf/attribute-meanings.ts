import { dwarfLanguageName } from "../../analyzers/dwarf/constants.js";

// DWARF 5 sections 7.6/7.8-7.17: enums are source facts, rather than addresses.
// https://dwarfstd.org/doc/DWARF5.pdf
const meanings = new Map<number, Map<bigint, string>>([
  [0x09, new Map([[0n, "row major"], [1n, "column major"]])],
  [0x17, new Map([[1n, "local"], [2n, "exported"], [3n, "qualified"]])],
  [0x20, new Map([[0n, "not inlined"], [1n, "inlined"],
    [2n, "declared inline; not inlined"], [3n, "declared inline; inlined"]])],
  [0x32, new Map([[1n, "public"], [2n, "protected"], [3n, "private"]])],
  [0x36, new Map([[1n, "normal"], [2n, "program"], [3n, "no call"],
    [4n, "pass by reference"], [5n, "pass by value"]])],
  [0x3e, new Map([[1n, "address"], [2n, "boolean"], [3n, "complex float"],
    [4n, "float"], [5n, "signed integer"], [6n, "signed character"],
    [7n, "unsigned integer"], [8n, "unsigned character"], [9n, "imaginary float"],
    [10n, "packed decimal"], [11n, "numeric string"], [12n, "edited"],
    [13n, "signed fixed point"], [14n, "unsigned fixed point"], [15n, "decimal float"],
    [16n, "UTF"], [17n, "UCS"], [18n, "ASCII"]])],
  [0x42, new Map([[0n, "case sensitive"], [1n, "uppercase"],
    [2n, "lowercase"], [3n, "case insensitive"]])],
  [0x4c, new Map([[0n, "nonvirtual"], [1n, "virtual"], [2n, "pure virtual"]])],
  [0x5e, new Map([[1n, "unsigned"], [2n, "leading overpunch"],
    [3n, "trailing overpunch"], [4n, "leading separate"], [5n, "trailing separate"]])],
  [0x65, new Map([[0n, "default byte order"], [1n, "big endian"], [2n, "little endian"]])]
]);

export const dwarfAttributeMeaning = (name: number, value: bigint): string => {
  if (name === 0x13 && value >= 0n && value <= BigInt(Number.MAX_SAFE_INTEGER)) {
    return dwarfLanguageName(Number(value)).replace("DW_LANG_", "")
      .replace("C_plus_plus", "C++").replaceAll("_", " ");
  }
  return meanings.get(name)?.get(value) ?? value.toString();
};
