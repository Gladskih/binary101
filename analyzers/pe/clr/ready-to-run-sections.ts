import type { FileRangeReader } from "../../file-range-reader.js";
import { readMappedRvaPrefix } from "../rva-byte-reader.js";
import type { RvaToOffset } from "../types.js";
import { parseReadyToRunImports } from "./ready-to-run-imports.js";
import { parseReadyToRunMethods } from "./ready-to-run-methods.js";
import { parseReadyToRunInstanceMethods } from "./ready-to-run-instance-methods.js";
import type { PeClrReadyToRunSection, PeClrReadyToRunSectionData } from "./ready-to-run-types.js";

// These layouts follow readytorun.h and ReadyToRunReader at the same release tag.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/inc/readytorun.h
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.Reflection.ReadyToRun/ReadyToRunReader.cs
const readText = (view: DataView): string => {
  const bytes = new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
  const terminator = bytes.indexOf(0);
  return new TextDecoder("utf-8", { fatal: true }).decode(
    terminator === -1 ? bytes : bytes.subarray(0, terminator));
};

const readOwnerName = (view: DataView, issues: Set<string>): PeClrReadyToRunSectionData => {
  if (!new Uint8Array(view.buffer, view.byteOffset, view.byteLength).includes(0)) {
    issues.add("OwnerCompositeExecutable has no NUL terminator.");
  }
  return { kind: "text", text: readText(view) };
};

const readHotColdMap = (view: DataView, issues: Set<string>): PeClrReadyToRunSectionData => {
  const entries: { coldRuntimeFunction: number; hotRuntimeFunction: number }[] = [];
  if (view.byteLength % 8) issues.add("HotColdMap ends with an incomplete entry.");
  for (let offset = 0; offset + 8 <= view.byteLength; offset += 8) {
    entries.push({ coldRuntimeFunction: view.getUint32(offset, true),
      hotRuntimeFunction: view.getUint32(offset + 4, true) });
  }
  return { kind: "hot-cold", entries };
};

const readComponents = (view: DataView, issues: Set<string>): PeClrReadyToRunSectionData => {
  const entries: { clrRva: number; clrSize: number;
    coreHeaderRva: number; coreHeaderSize: number }[] = [];
  if (view.byteLength % 16) issues.add("ComponentAssemblies ends with an incomplete entry.");
  for (let offset = 0; offset + 16 <= view.byteLength; offset += 16) {
    entries.push({ clrRva: view.getUint32(offset, true),
      clrSize: view.getUint32(offset + 4, true),
      coreHeaderRva: view.getUint32(offset + 8, true),
      coreHeaderSize: view.getUint32(offset + 12, true) });
  }
  return { kind: "components", entries };
};

const fixedDecoders: Readonly<Record<number,
  (view: DataView, issues: Set<string>) => PeClrReadyToRunSectionData>> = {
  // CompilerIdentifierNode emits counted ASCII bytes without a NUL terminator.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.ReadyToRun/Compiler/DependencyAnalysis/ReadyToRun/CompilerIdentifierNode.cs
  100: view => ({ kind: "text", text: readText(view) }),
  103: (view, issues) => ({ kind: "methods", methods: parseReadyToRunMethods(
    new Uint8Array(view.buffer, view.byteOffset, view.byteLength), issues) }),
  109: (view, issues) => ({ kind: "instance-methods", methods: parseReadyToRunInstanceMethods(
    new Uint8Array(view.buffer, view.byteOffset, view.byteLength), issues) }),
  115: readComponents,
  116: readOwnerName,
  120: readHotColdMap
};

export type ReadyToRunSectionCache = Map<string, {
  decoded?: PeClrReadyToRunSectionData; warnings: string[]
}>;

const decodeSection = async (
  reader: FileRangeReader, mapper: RvaToOffset, section: PeClrReadyToRunSection,
  pointerSize: 4 | 8 | undefined
): Promise<{ decoded?: PeClrReadyToRunSectionData; warnings: string[] }> => {
  const warnings = new Set<string>();
  try {
    const view = await readMappedRvaPrefix(reader, section.rva, section.size, mapper);
    if (view.byteLength < section.size) warnings.add(`${section.name} section is truncated.`);
    return { decoded: section.type === 101
      ? { kind: "imports", imports: await parseReadyToRunImports(
        view, reader, mapper, pointerSize, warnings) }
      : fixedDecoders[section.type]!(view, warnings), warnings: [...warnings] };
  } catch (error) {
    warnings.add(`${section.name}: ${error instanceof Error ? error.message : "decoding failed"}`);
    return { warnings: [...warnings] };
  }
};

export const decodeReadyToRunSections = async (
  reader: FileRangeReader, mapper: RvaToOffset, sections: PeClrReadyToRunSection[],
  pointerSize: 4 | 8 | undefined, issues: string[], cache: ReadyToRunSectionCache = new Map()
): Promise<void> => {
  const warnings = new Set<string>();
  for (const section of sections) {
    if (!fixedDecoders[section.type] && section.type !== 101) continue;
    // Composite core headers can reference identical sections; decode their bytes once per image.
    const key = `${section.type}/${section.rva}/${section.size}`;
    const result = cache.get(key) ?? await decodeSection(reader, mapper, section, pointerSize);
    cache.set(key, result);
    if (result.decoded) section.decoded = result.decoded;
    result.warnings.forEach(message => warnings.add(message));
  }
  issues.push(...warnings);
};
