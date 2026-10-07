import { readDwarfPublicNames } from "./public-names.js";
import { readDwarfAddressLookup } from "./address-lookup.js";
import { readDwarfNameIndex } from "./name-index.js";
import type { DwarfAnalysis, DwarfSectionSource, DwarfUnit } from "./types.js";
import type { DwarfStringReader } from "./strings.js";

export const readDwarfLookups = async (sections: Map<string, DwarfSectionSource>, units: DwarfUnit[],
  byteOrder: "little" | "big", strings: DwarfStringReader, issues: string[]): Promise<
    Pick<DwarfAnalysis, "publicNames" | "addressLookup" | "nameIndexes">
  > => {
  const publicNames: NonNullable<DwarfAnalysis["publicNames"]> = [];
  for (const name of [".debug_pubnames", ".debug_pubtypes", ".debug_gnu_pubnames", ".debug_gnu_pubtypes"]) {
    const source = sections.get(name);
    if (source) publicNames.push(...await readDwarfPublicNames(source, units, byteOrder, issues));
  }
  const addresses = sections.get(".debug_aranges");
  const names = sections.get(".debug_names");
  return {
    ...(publicNames.length ? { publicNames } : {}),
    ...(addresses ? { addressLookup: await readDwarfAddressLookup(addresses, units, byteOrder, issues) } : {}),
    ...(names ? { nameIndexes: await readDwarfNameIndex(names, units, byteOrder, strings, issues) } : {})
  };
};
