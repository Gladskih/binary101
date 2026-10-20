import type { PortablePdbSource } from "./portable-pdb-source.js";

export interface PortablePdbCompilationReference {
  fileName: string;
  aliases: string;
  flags: number;
  timeStamp: number;
  fileSize: number;
  mvid: string | null;
}

export type PortablePdbCustomData =
  | { type: "sourceLink"; documents: { pattern: string; url: string }[] }
  | { type: "options"; options: { name: string; value: string }[] }
  | { type: "references"; references: PortablePdbCompilationReference[] }
  | { type: "tupleNames"; names: string[] }
  | { type: "defaultNamespace"; name: string }
  | { type: "embeddedSource"; source: PortablePdbSource | null }
  | { type: "hoistedScopes"; scopes: number; inactiveScopes: number; totalIlBytes: number }
  | { type: "dynamicFlags"; setBits: number; storedBits: number }
  | { type: "encSlots"; slots: number; temporaries: number; ordinalSlots: number }
  | { type: "encLambdas"; closures: number; lambdas: number }
  | { type: "encStates"; states: number }
  | { type: "asyncStepping"; hasCatchHandler: boolean; awaits: number }
  | { type: "typeDocuments"; documents: number[] }
  | { type: "primaryConstructor" };
