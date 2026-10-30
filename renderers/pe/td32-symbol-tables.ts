import type { PeTd32Info } from "../../analyzers/pe/debug/td32.js";
import type { Td32Table } from "./td32-tables.js";
import type { Td32SymbolRecord } from "../../analyzers/pe/debug/td32-symbol-types.js";
import { analyzeTd32SymbolLinks, type Td32ScopeLinks } from "../../analyzers/pe/debug/td32-symbol-links.js";
import { td32SymbolKind, td32SymbolName, td32SymbolPlacement, td32SymbolProperties } from "./td32-symbol-properties.js";

interface SymbolTables {
  procedures: Td32Table;
  variables: Td32Table;
  imports: Td32Table;
  totals: Map<string, bigint>;
  generation: number;
  module: number;
  names: readonly string[];
}

const increment = (state: SymbolTables, name: string, value = 1n): void => {
  state.totals.set(name, (state.totals.get(name) ?? 0n) + value);
};

const debugBytes = (record: Td32SymbolRecord): string => {
  const metadata = record.metadata!;
  const span = metadata.debugRange;
  if (!span) return "not stored";
  return span.start <= span.end && span.end <= metadata.codeLength! ? String(span.end - span.start) : "invalid debug span";
};

const procedure = (state: SymbolTables, record: Td32SymbolRecord, links: Td32ScopeLinks | undefined): void => {
  const metadata = record.metadata!;
  state.procedures.rows.push([td32SymbolName(state.names, record.nameIndex),
    String(metadata.codeLength), debugBytes(record),
    td32SymbolPlacement(metadata), links?.parent ? td32SymbolName(state.names, links.parent.nameIndex)
      : metadata.scopeOffsets?.parent === 0 ? "(root)" : "(unresolved parent)",
    links?.issues.join("; ") || "link targets verified", String(state.generation), String(state.module)]);
  increment(state, "Procedure / thunk descriptions");
  increment(state, "Procedure code bytes (sum)", BigInt(metadata.codeLength!));
};

const variable = (state: SymbolTables, record: Td32SymbolRecord): void => {
  const metadata = record.metadata!;
  state.variables.rows.push([td32SymbolName(state.names, record.nameIndex), td32SymbolKind(record.type),
    metadata.typeIndex === undefined ? "not stored" : `stored type #${metadata.typeIndex}`,
    td32SymbolPlacement(metadata), td32SymbolProperties(record, state.names),
    String(state.generation), String(state.module)]);
};

const countAnonymous = (state: SymbolTables, record: Td32SymbolRecord): void => {
  const metadata = record.metadata!;
  if (record.type === 0x211) {
    increment(state, "Optimized location descriptions");
    increment(state, "Optimized range bytes (sum)", BigInt(metadata.codeLength!));
  }
  if (record.type === 0x212) increment(state, "Epilogue bytes (sum)", BigInt(metadata.codeLength!));
  if (record.type === 0x213) increment(state, "Saved-register descriptions");
  if (metadata.frameOffset !== undefined) increment(state, "Stored BP-relative descriptions");
  if (metadata.register !== undefined) increment(state, "Register location descriptions");
  if (record.type === 0x20 || record.type === 0x21) increment(state, "Procedure / data references");
};

const addRecord = (state: SymbolTables, record: Td32SymbolRecord, links: Td32ScopeLinks | undefined): void => {
  const metadata = record.metadata;
  if (!metadata) return;
  if ([0x204, 0x205, 0x206].includes(record.type)) procedure(state, record, links);
  else if (record.nameIndex !== undefined) variable(state, record);
  for (const name of metadata.nameIndices ?? []) state.imports.rows.push([
    td32SymbolName(state.names, name), td32SymbolKind(record.type), String(state.generation), String(state.module)]);
  countAnonymous(state, record);
};

/** Summaries describe stored encodings; they do not infer parameters, frame bases, RVAs or runtime values. */
export const buildTd32SymbolTables = (info: PeTd32Info): Td32Table[] => {
  const state: SymbolTables = {
    procedures: { key: "procedures", title: "TD32 procedures and thunks", columns: ["Name", "Code bytes", "Debug bytes",
      "Stored placement", "Parent scope", "Scope links", "Directory", "Module"], rows: [] },
    variables: { key: "symbolmetadata", title: "TD32 symbol properties and placement", columns: ["Name", "Symbol kind",
      "Type reference", "Stored placement", "Properties", "Directory", "Module"], rows: [] },
    imports: { key: "imports", title: "TD32 imported units and using declarations", columns: ["Name", "Declaration",
      "Directory", "Module"], rows: [] }, totals: new Map(), generation: 0, module: 0, names: []
  };
  for (const [generation, directory] of info.directories.entries()) {
    state.generation = generation + 1;
    const tables = directory.subsections.flatMap(section => section.data?.kind === "names" ? [section.data.names] : []);
    state.names = tables.length === 1 ? tables[0]! : [];
    for (const section of directory.subsections) {
      if (section.data?.kind !== "symbols") continue;
      state.module = section.module;
      const links = analyzeTd32SymbolLinks(section.data);
      for (const record of section.data.records) addRecord(state, record, links.get(record));
    }
  }
  return [{ key: "semantics", title: "TD32 symbol semantic statistics", columns: ["Property", "Count / bytes"],
    rows: [...state.totals].map(([name, count]) => [name, String(count)]) },
  state.procedures, state.variables, state.imports]
    .filter(table => table.rows.length);
};
