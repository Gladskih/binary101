"use strict";

import { isPeWindowsParseResult, type PeParseResult, type PeWindowsParseResult } from "../analyzers/pe/index.js";
import { loadClrDependency } from "../analyzers/pe/clr/metadata-dependency-loader.js";
import { resolveClrMetadataDependencies } from "../analyzers/pe/clr/metadata-dependencies.js";
import type { PeClrMetadataTables } from "../analyzers/pe/clr/types.js";

interface LoadedDependency { tables: PeClrMetadataTables | null; issues: string[]; }
interface ClrDependencySelection { assemblies: PeClrMetadataTables[]; issues: string[]; }

const dependencyInput = (event: Event): HTMLInputElement | null => {
  const input = event.target;
  if (!(input instanceof HTMLInputElement)) return null;
  if (!input.hasAttribute("data-clr-dependencies") || input.disabled) return null;
  return input.files?.length ? input : null;
};

const readDependency = async (file: File): Promise<LoadedDependency> => {
  const issues: string[] = [];
  return { tables: await loadClrDependency(file, issues), issues };
};

const readSelection = async (
  selectedFiles: File[], files: WeakMap<File, Promise<LoadedDependency>>
): Promise<ClrDependencySelection> => {
  const assemblies: PeClrMetadataTables[] = [];
  const issues: string[] = [];
  for (const file of new Set(selectedFiles)) {
    if (!files.has(file)) files.set(file, readDependency(file));
    const loaded = await files.get(file)!;
    issues.push(...loaded.issues);
    if (loaded.tables) assemblies.push(loaded.tables);
  }
  return { assemblies, issues };
};

const resolveSelection = (tables: PeClrMetadataTables, selected: ClrDependencySelection): PeClrMetadataTables => {
  const updated = resolveClrMetadataDependencies(tables, selected.assemblies);
  if (selected.issues.length) updated.issues = [...updated.issues ?? [], ...selected.issues];
  return updated;
};

export const createClrDependencyChangeHandler = (
  getCurrentPe: () => PeWindowsParseResult | null, setStatus: (message: string) => void,
  onUpdated: (pe: PeWindowsParseResult) => void
): (event: Event) => Promise<void> => {
  const files = new WeakMap<File, Promise<LoadedDependency>>();
  let generation = 0;
  return async event => {
    const input = dependencyInput(event);
    if (!input) return;
    const pe = getCurrentPe();
    if (!pe) return;
    const metadata = pe.clr?.meta;
    if (!metadata?.tables) return;
    const requestGeneration = ++generation;
    input.disabled = true;
    setStatus("Reading local assembly dependencies...");
    const selected = await readSelection(Array.from(input.files!), files);
    input.disabled = false;
    input.value = "";
    if (getCurrentPe() !== pe || generation !== requestGeneration) return;
    metadata.tables = resolveSelection(metadata.tables, selected);
    onUpdated(pe);
    setStatus(`Loaded ${selected.assemblies.length} local assembly dependencies.`);
  };
};

export const attachClrDependencyInputs = (
  root: ParentNode, getCurrentPe: () => PeParseResult | undefined,
  onUpdated: (pe: PeWindowsParseResult) => void
): void => {
  const handler = createClrDependencyChangeHandler(() => {
    const current = getCurrentPe();
    return current && isPeWindowsParseResult(current) ? current : null;
  }, message => {
    const status = document.getElementById("statusMessage");
    if (status) status.textContent = message;
  }, onUpdated);
  root.addEventListener("change", event => { void handler(event); });
};
