import type { WasmParseResult } from "./types.js";

const checkIndex = (result: WasmParseResult, label: string, index: number, count: number): void => {
  if (index >= count) result.issues.push(`${label}: index ${index} is outside ${count} entries`);
};

const functionTypeIndex = (result: WasmParseResult, index: number): number | undefined => {
  const imports = result.imports.filter(entry => entry.descriptor.kind === "function");
  const descriptor = imports[index]?.descriptor;
  return descriptor?.kind === "function" ? descriptor.typeIndex :
    result.functions[index - imports.length]?.typeIndex;
};

const validateExports = (result: WasmParseResult, counts: Record<string, number>): void => {
  const exportedNames = new Set<string>();
  for (const entry of result.exports) {
    checkIndex(result, `Export ${entry.name}`, entry.index, counts[entry.kind] ?? 0);
    if (exportedNames.has(entry.name)) result.issues.push(`Duplicate export name: ${entry.name}`);
    exportedNames.add(entry.name);
  }
};

const validateCountsAndStart = (result: WasmParseResult, counts: Record<string, number>): void => {
  if (result.functions.length !== result.code.length) {
    result.issues.push(`Function/code count mismatch: ${result.functions.length}/${result.code.length}`);
  }
  if (result.dataCount !== null && result.dataCount !== result.data.length) {
    result.issues.push(`Data count mismatch: ${result.dataCount}/${result.data.length}`);
  }
  if (result.start !== null) {
    checkIndex(result, "Start function", result.start, counts["function"]!);
    const type = result.types[functionTypeIndex(result, result.start) ?? -1];
    if (type && (type.params.length || type.results.length)) {
      result.issues.push("Start function must have no parameters or results");
    }
  }
};

export const validateReferences = (result: WasmParseResult): void => {
  if (result.sections.some(section => section.id !== 0 && section.status === "partial")) {
    result.issues.push("Cross-section checks are incomplete because a core section was not fully decoded");
    return;
  }
  const counts: Record<string, number> = { function: result.functions.length,
    table: result.tables.length, memory: result.memories.length,
    global: result.globals.length, tag: result.tags.length };
  for (const entry of result.imports) {
    counts[entry.descriptor.kind] = counts[entry.descriptor.kind]! + 1;
  }
  const declarations = [...result.functions, ...result.imports.map(entry => entry.descriptor)
    .filter(entry => entry.kind === "function" || entry.kind === "tag")];
  for (const entry of declarations) checkIndex(result, "Type reference", entry.typeIndex, result.types.length);
  for (const typeIndex of result.tags) checkIndex(result, "Tag type", typeIndex, result.types.length);
  validateExports(result, counts);
  validateCountsAndStart(result, counts);
  validateSegments(result, counts);
};

const validateSegments = (result: WasmParseResult, counts: Record<string, number>): void => {
  for (const segment of result.data) {
    if (segment.memory !== null) checkIndex(result, "Data memory", segment.memory, counts["memory"]!);
  }
  for (const segment of result.elements) {
    if (segment.table !== null) checkIndex(result, "Element table", segment.table, counts["table"]!);
    for (const entry of segment.entries) {
      if (typeof entry === "number") checkIndex(result, "Element function", entry, counts["function"]!);
    }
  }
  for (const key of Object.keys(result.functionNames)) {
    checkIndex(result, "Function name", Number(key), counts["function"]!);
  }
};
