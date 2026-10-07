import { readDwarfInformation } from "./information.js";
import { parseDwarfLines } from "./lines.js";
import { validateDwarfLines } from "./line-validation.js";
import { decodeDwarfDieLists } from "./die-lists.js";
import { readDwarfMacros } from "./macros.js";
import { dwarfSplitScopes, type DwarfSplitScope } from "./split-sources.js";
import { readDwarfPackageIndex } from "./package-index.js";
import { validateDwarfPackageUnits } from "./package-unit-validation.js";
import type { DwarfStringReader } from "./strings.js";
import type { DwarfMacroUnit } from "./macro-types.js";
import type { DwarfPackageIndex } from "./package-types.js";
import type { DwarfLineProgram, DwarfSectionSource, DwarfUnit } from "./types.js";

const rebaseUnit = (unit: DwarfUnit, base: number): DwarfUnit => ({ ...unit,
  offset: unit.offset + base, dies: unit.dies.map(die => ({ ...die,
    offset: die.offset + base, parentOffset: die.parentOffset == null ? null : die.parentOffset + base })) });

const rebaseMacro = (macro: DwarfMacroUnit, base: number): DwarfMacroUnit => ({ ...macro,
  sectionName: macro.sectionName + ".dwo", offset: macro.offset + base,
  entries: macro.entries.map(entry => ({ ...entry, offset: entry.offset + base })) });

const readScope = async (scope: DwarfSplitScope, strings: DwarfStringReader,
  byteOrder: "little" | "big", skeletons: DwarfUnit[], issues: string[]) => {
  const scopedStrings = strings.scoped(scope.sections);
  const units = await readDwarfInformation([".debug_info", ".debug_types"]
    .flatMap(name => scope.sections.get(name) ? [scope.sections.get(name)!] : []),
  scope.sections, byteOrder, issues, scopedStrings);
  const lines = scope.sections.get(".debug_line");
  const programs = lines ? await parseDwarfLines(lines, scope.sections,
    byteOrder === "little", issues, scopedStrings) : [];
  validateDwarfLines(programs, units, issues);
  const macros = await readDwarfMacros(scope.sections, units, byteOrder, issues, scopedStrings);
  return {
    units: (await decodeDwarfDieLists(units, scope.sections, byteOrder, issues, skeletons))
      .map(unit => rebaseUnit(unit,
        scope.contributions.get(unit.sectionName.slice(0, -4))?.offset ?? 0)),
    linePrograms: programs.map(program => ({ ...program, sectionName: ".debug_line.dwo",
      offset: program.offset + (scope.contributions.get(".debug_line")?.offset ?? 0) })),
    macros: macros.map(macro => rebaseMacro(macro,
      scope.contributions.get(macro.sectionName)?.offset ?? 0))
  };
};

export const readDwarfSplitInformation = async (sections: Map<string, DwarfSectionSource>,
  strings: DwarfStringReader, byteOrder: "little" | "big", skeletons: DwarfUnit[], issues: string[]) => {
  const packageIndexes: DwarfPackageIndex[] = [];
  for (const name of [".debug_cu_index", ".debug_tu_index"]) {
    const source = sections.get(name);
    const index = source ? await readDwarfPackageIndex(source, sections, byteOrder, issues) : null;
    if (index) packageIndexes.push(index);
  }
  const units: DwarfUnit[] = [];
  const linePrograms: DwarfLineProgram[] = [];
  const macros: DwarfMacroUnit[] = [];
  for (const scope of dwarfSplitScopes(sections, packageIndexes, issues)) {
    const parsed = await readScope(scope, strings, byteOrder, skeletons, issues);
    units.push(...parsed.units);
    linePrograms.push(...parsed.linePrograms);
    macros.push(...parsed.macros);
  }
  validateDwarfPackageUnits(packageIndexes, units, issues);
  return { units, linePrograms, macros, packageIndexes };
};
