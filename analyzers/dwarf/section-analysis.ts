import { DwarfStringReader } from "./strings.js";
"use strict";

import { DWARF_SECTION } from "./constants.js";
import { readDwarfInformation } from "./information.js";
import { parseDwarfLines } from "./lines.js";
import { validateDwarfLines } from "./line-validation.js";
import { createDwarfDieIndex, validateDwarfReferences } from "./references.js";
import { decodeDwarfDieExpressions } from "./die-expressions.js";
import { decodeDwarfDieLists } from "./die-lists.js";
import { readDwarfMacros } from "./macros.js";
import { readDwarfLookups } from "./lookups.js";
import { readDwarfFrames } from "./frames.js";
import { readDwarfSplitInformation } from "./split-information.js";
import { readDwarfExternalFiles, validateDwarfSplitFiles } from "./external-files.js";
import type { DwarfSectionSource } from "./types.js";

export const readDwarfSectionAnalysis = async (sectionMap: Map<string, DwarfSectionSource>,
  byteOrder: "little" | "big", addressSize: number, machine: number, issues: string[]) => {
  const littleEndian = byteOrder === "little";
  const infoSections = [
    sectionMap.get(DWARF_SECTION.information),
    sectionMap.get(DWARF_SECTION.types)
  ]
    .filter((source): source is DwarfSectionSource =>
      source != null && source.section.size > 0);
  const strings = new DwarfStringReader(sectionMap, byteOrder, issues);
  const regularUnits = await readDwarfInformation(infoSections, sectionMap, byteOrder, issues, strings);
  const split = await readDwarfSplitInformation(sectionMap, strings, byteOrder, regularUnits, issues);
  const units = [...regularUnits, ...split.units];
  validateDwarfSplitFiles(units, issues);
  const lineSource = sectionMap.get(DWARF_SECTION.lines);
  validateDwarfReferences(createDwarfDieIndex(units), issues);
  const regularLines = lineSource && lineSource.section.size > 0
    ? await parseDwarfLines(lineSource, sectionMap, littleEndian, issues, strings)
    : [];
  const linePrograms = [...regularLines, ...split.linePrograms];
  const decodedUnits = [...await decodeDwarfDieLists(regularUnits, sectionMap, byteOrder, issues), ...split.units];
  validateDwarfLines(regularLines, regularUnits, issues);
  const macros = [...await readDwarfMacros(sectionMap, regularUnits, byteOrder, issues, strings), ...split.macros];
  const frameSource = sectionMap.get(".debug_frame");
  const frames = frameSource ? await readDwarfFrames(frameSource, byteOrder,
    addressSize, machine, issues) : null;
  return { units: await decodeDwarfDieExpressions(decodedUnits, byteOrder, issues),
    linePrograms, ...(macros.length ? { macros } : {}), ...(frames ? { frames } : {}),
    ...(split.packageIndexes.length ? { packageIndexes: split.packageIndexes } : {}),
    ...await readDwarfLookups(sectionMap, units, byteOrder, strings, issues),
    ...await readDwarfExternalFiles(sectionMap, byteOrder, issues) };
};
