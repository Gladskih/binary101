import type { PeClrReadyToRunSection, PeClrReadyToRunSectionData } from
  "../../analyzers/pe/clr/ready-to-run-types.js";
import type { AnalysisStatistic } from "../analysis-statistics.js";
import { readyToRunDebugStatistics } from "./ready-to-run-debug-statistics.js";

const fact = (label: string, value: number, description: string): AnalysisStatistic => ({ label, value, description });

const methodStatistics = (data: Extract<PeClrReadyToRunSectionData, { kind: "methods" | "instance-methods" }>) => [
  fact(data.kind === "methods" ? "Method-definition entry points" : "Instantiated method entry points",
    data.methods.length, data.kind === "methods" ? "Compiled methods linked to managed method definitions." :
      "Compiled generic instantiations identified by native signatures."),
  fact("Methods with fixups", data.methods.filter(method => method.fixupOffset !== null).length,
    "These methods carry dependencies the runtime must resolve before execution.")
];

const thunkStatistics = (data: Extract<PeClrReadyToRunSectionData, { kind: "thunks" }>): AnalysisStatistic[] => {
  const kinds = new Map<string, number>();
  for (const thunk of data.entries) kinds.set(thunk.kind, (kinds.get(thunk.kind) ?? 0) + 1);
  return [fact("Import thunks", data.entries.length,
    "Small compiler-generated routines call the runtime to bind or dispatch imported code."),
  ...[...kinds].map(([kind, count]) => fact(`${kind} thunks`, count,
    "Validated instruction templates contribute code starts; their cells, literals and padding remain data."))];
};

export const readyToRunSectionStatistics = (section: PeClrReadyToRunSection): AnalysisStatistic[] => {
  const data = section.decoded;
  if (!data || data.kind === "text") return [];
  if (data.kind === "debug-info") return readyToRunDebugStatistics(data.methods);
  if (data.kind === "components") return [
    fact("Component assemblies", data.entries.length, "A composite image can hold native code for several assemblies."),
    fact("Decoded component headers", data.entries.filter(entry => entry.coreHeader).length,
      "Each readable component directory contributes its own method and import maps.")
  ];
  if (data.kind === "methods" || data.kind === "instance-methods") return methodStatistics(data);
  if (data.kind === "hot-cold") return [fact("Hot/cold code pairs", data.entries.length,
    "Rarely executed code is separated from the hot path to improve locality.")];
  if (data.kind === "imports") return [
    fact("Import tables", data.imports.length, "Groups of runtime-resolved references used by compiled code."),
    fact("Import cells", data.imports.reduce((count, table) => count + table.entries.length, 0),
      "Dependency cells contain data and must not become instruction seeds."),
    fact("Import cells with signatures", data.imports.reduce((count, table) => count +
      table.entries.filter(entry => entry.signatureRva !== null).length, 0),
    "Signatures describe which runtime dependency a cell needs.")
  ];
  return thunkStatistics(data);
};

export const readyToRunStatistics = (sections: PeClrReadyToRunSection[]): AnalysisStatistic[] => {
  const facts = new Map<string, AnalysisStatistic>();
  for (const section of sections) {
    for (const statistic of readyToRunSectionStatistics(section)) {
      const previous = facts.get(statistic.label);
      facts.set(statistic.label, previous ? { ...statistic, value: previous.value + statistic.value } : statistic);
    }
  }
  return [...facts.values()];
};
