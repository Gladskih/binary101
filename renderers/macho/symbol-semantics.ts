"use strict";

import {
  DYNAMIC_LOOKUP_ORDINAL,
  EXECUTABLE_ORDINAL,
  N_EXT,
  N_INDR,
  N_PEXT,
  SELF_LIBRARY_ORDINAL,
  N_STAB,
  N_TYPE,
  N_UNDF,
  N_WEAK_DEF,
  N_WEAK_REF,
  REFERENCED_DYNAMICALLY
} from "../../analyzers/macho/commands.js";
import { symbolTypeName } from "../../analyzers/macho/load-command-info.js";
import type { MachOImage, MachOSymbol } from "../../analyzers/macho/types.js";

const sectionNameByIndex = (image: MachOImage, sectionIndex: number): string | null => {
  if (sectionIndex === 0) return null;
  for (const segment of image.segments) {
    for (const section of segment.sections) {
      if (section.index === sectionIndex) return section.sectionName;
    }
  }
  return null;
};

const symbolIsDebug = (type: number): boolean => (type & N_STAB) !== 0;
const symbolIsExternal = (type: number): boolean => (type & N_EXT) !== 0;
const symbolIsPrivateExternal = (type: number): boolean => (type & N_PEXT) !== 0;
const symbolTypeBits = (type: number): number => type & N_TYPE;

const symbolTypeLabelFor = (symbol: MachOSymbol): string =>
  symbolIsDebug(symbol.type) ? "Debug / STAB" : symbolTypeName(symbolTypeBits(symbol.type));

const symbolDescriptionLabels = (symbol: MachOSymbol): string[] => {
  const labels: string[] = [];
  const typeBits = symbolTypeBits(symbol.type);
  const referenceType = symbol.description & 0x7;
  if (typeBits === N_UNDF) {
    if (referenceType === 0) labels.push("Undefined (non-lazy)");
    else if (referenceType === 1) labels.push("Undefined (lazy)");
    else if (referenceType === 4) labels.push("Private undefined (non-lazy)");
    else if (referenceType === 5) labels.push("Private undefined (lazy)");
  }
  if ((symbol.description & REFERENCED_DYNAMICALLY) !== 0) labels.push("Referenced dynamically");
  if ((symbol.description & N_WEAK_REF) !== 0) labels.push("Weak reference");
  if ((symbol.description & N_WEAK_DEF) !== 0) {
    labels.push(typeBits === N_UNDF ? "Reference to weak symbol" : "Weak definition");
  }
  return labels;
};

const symbolLibraryLabel = (image: MachOImage, symbol: MachOSymbol): string | null => {
  if (symbol.libraryOrdinal == null) return null;
  if (
    symbol.libraryOrdinal === SELF_LIBRARY_ORDINAL &&
    symbolIsExternal(symbol.type) &&
    symbolTypeBits(symbol.type) !== N_UNDF
  ) {
    return "This image";
  }
  if (symbol.libraryOrdinal === EXECUTABLE_ORDINAL) return "Main executable";
  if (
    symbol.libraryOrdinal === DYNAMIC_LOOKUP_ORDINAL &&
    symbolTypeBits(symbol.type) === N_UNDF &&
    image.dylibs.length < DYNAMIC_LOOKUP_ORDINAL
  ) {
    return "Dynamic lookup";
  }
  return image.dylibs[symbol.libraryOrdinal - 1]?.name || `Dylib #${symbol.libraryOrdinal}`;
};

const symbolBindingLabels = (image: MachOImage, symbol: MachOSymbol): string[] => {
  const labels = [
    symbolIsExternal(symbol.type) ? "external" : "local",
    symbolIsPrivateExternal(symbol.type) ? "private-external" : "",
    symbolLibraryLabel(image, symbol) || ""
  ];
  return labels.filter(Boolean);
};

const summarizeSymbols = (symbols: MachOSymbol[]): {
  debug: number;
  externalDefined: number;
  indirect: number;
  local: number;
  undefined: number;
} => {
  let debug = 0;
  let externalDefined = 0;
  let indirect = 0;
  let local = 0;
  let undefinedCount = 0;
  for (const symbol of symbols) {
    const typeBits = symbolTypeBits(symbol.type);
    if (symbolIsDebug(symbol.type)) debug += 1;
    else if (!symbolIsExternal(symbol.type)) local += 1;
    else if (typeBits === N_UNDF) undefinedCount += 1;
    else if (typeBits === N_INDR) indirect += 1;
    else externalDefined += 1;
  }
  return { debug, externalDefined, indirect, local, undefined: undefinedCount };
};

export {
  sectionNameByIndex,
  summarizeSymbols,
  symbolBindingLabels,
  symbolDescriptionLabels,
  symbolTypeLabelFor
};
