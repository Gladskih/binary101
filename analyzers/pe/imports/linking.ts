"use strict";

import type { PeBoundImportEntry } from "./bound.js";
import type { PeDelayImportEntry } from "./delay.js";
import type { PeIatDirectory } from "./iat.js";
import type { PeImportParseResult } from "./index.js";
import type { PeLoadConfig } from "../load-config/index.js";
import type { PeSection } from "../types.js";
import { analyzeInferredEagerIat } from "./inferred-eager.js";
import {
  analyzeLinkedModule,
  resolveIatDirectoryRelation
} from "./linking-findings.js";
import type {
  PeImportLinkingModule,
  PeImportLinkingResult
} from "./linking-model.js";

export type {
  PeIatDirectoryRelation,
  PeDeclaredIatRelation,
  PeImportBindingRelation,
  PeImportLinkingFinding,
  PeLinkedImportDescriptor,
  PeLinkedBoundImportDescriptor,
  PeLinkedDelayImportDescriptor,
  PeInferredEagerIat,
  PeImportLinkingModule,
  PeImportLinkingResult
} from "./linking-model.js";

const normalizeModuleKey = (name: string, prefix: string, index: number): string => {
  const normalized = name.trim().toLowerCase();
  return normalized || `#${prefix}-${index}`;
};

const getOrCreateLinkedModule = (
  modulesByKey: Map<string, PeImportLinkingModule>,
  moduleKey: string
): PeImportLinkingModule => {
  const existing = modulesByKey.get(moduleKey);
  if (existing) return existing;
  const linkedModule: PeImportLinkingModule = {
    moduleKey,
    imports: [],
    boundImports: [],
    delayImports: []
  };
  modulesByKey.set(moduleKey, linkedModule);
  return linkedModule;
};

const addImportDescriptors = (
  modulesByKey: Map<string, PeImportLinkingModule>,
  imports: PeImportParseResult,
  iat: PeIatDirectory | null
): void => {
  imports.entries.forEach((entry, index) => {
    getOrCreateLinkedModule(
      modulesByKey,
      normalizeModuleKey(entry.dll || "", "import", index)
    ).imports.push({
      importIndex: index,
      iatDirectoryRelation: resolveIatDirectoryRelation(entry.firstThunkRva, iat),
      bindingRelation: entry.timeDateStamp ? "timestamp-only" : "none"
    });
  });
};

const addBoundImportDescriptors = (
  modulesByKey: Map<string, PeImportLinkingModule>,
  boundImports: { entries: PeBoundImportEntry[] } | null
): void => {
  boundImports?.entries.forEach((entry, index) => {
    getOrCreateLinkedModule(
      modulesByKey,
      normalizeModuleKey(entry.name || "", "bound", index)
    ).boundImports.push({ boundImportIndex: index });
  });
};

const addDelayImportDescriptors = (
  modulesByKey: Map<string, PeImportLinkingModule>,
  delayImports: { entries: PeDelayImportEntry[] } | null,
  iat: PeIatDirectory | null
): void => {
  delayImports?.entries.forEach((entry, index) => {
    getOrCreateLinkedModule(
      modulesByKey,
      normalizeModuleKey(entry.name || "", "delay", index)
    ).delayImports.push({
      delayImportIndex: index,
      iatDirectoryRelation: resolveIatDirectoryRelation(entry.ImportAddressTableRVA, iat)
    });
  });
};

export const analyzeImportLinking = (
  imports: PeImportParseResult,
  boundImports: { entries: PeBoundImportEntry[] } | null,
  delayImports: { entries: PeDelayImportEntry[] } | null,
  iat: PeIatDirectory | null,
  loadcfg: PeLoadConfig | null,
  sections: PeSection[]
): PeImportLinkingResult | null => {
  if (!imports.entries.length && !boundImports?.entries.length && !delayImports?.entries.length) {
    return null;
  }
  const { inferredEagerIat, findings } = analyzeInferredEagerIat(imports, iat);
  const modulesByKey = new Map<string, PeImportLinkingModule>();
  addImportDescriptors(modulesByKey, imports, iat);
  addBoundImportDescriptors(modulesByKey, boundImports);
  addDelayImportDescriptors(modulesByKey, delayImports, iat);
  return {
    inferredEagerIat,
    ...(findings.length ? { findings } : {}),
    modules: [...modulesByKey.values()]
      .map(linkedModule =>
        analyzeLinkedModule(linkedModule, imports, delayImports, iat, loadcfg, sections)
      )
      .sort((left, right) => left.moduleKey.localeCompare(right.moduleKey))
  };
};
