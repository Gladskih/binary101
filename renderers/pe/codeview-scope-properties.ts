import type { LegacyCodeViewSymbol } from "../../analyzers/pe/debug/legacy-codeview-symbol-records.js";
import type { CodeViewScopeSymbol } from "../../analyzers/pe/debug/codeview-scope-types.js";

export const codeViewScopeName = (record?: LegacyCodeViewSymbol): string => {
  const scope = record?.scope;
  if (!scope) return "procedure scope";
  if (scope.kind === "inline") return scope.inlinee === undefined ? "inlinee unavailable" : `inlinee #${scope.inlinee}`;
  return `${scope.kind}: ${record?.name ?? "(name unavailable)"}`;
};

const inlineProperties = (record: LegacyCodeViewSymbol): string[] => {
  const scope = record.scope!;
  const result: string[] = [];
  if (scope.invocations !== undefined) result.push(`${scope.invocations} invocations`);
  const annotations = scope.annotations;
  if (!annotations) return [...result, "annotations unavailable"];
  let bytes = 0n;
  let files = 0;
  let chunks = 0;
  for (const annotation of annotations) {
    if (annotation.opcode === 4 || annotation.opcode === 12) bytes += BigInt(annotation.operands[0]!);
    if (annotation.opcode === 5) files++;
    if (annotation.opcode === 2) chunks++;
  }
  return [...result, `${annotations.length} annotations`, `${bytes} declared code bytes (sum)`,
    `${files} file changes`, `${chunks} chunk changes`];
};

const thunkProperties = (scope: CodeViewScopeSymbol): string => {
  const properties = [["standard", "adjustor", "virtual call", "pcode", "address load", "incremental trampoline",
    "branch island trampoline"][scope.ordinal ?? -1] ?? `unknown thunk ordinal ${scope.ordinal ?? "unavailable"}`];
  if (scope.adjustment !== undefined) properties.push(`this adjustment ${scope.adjustment}`);
  if (scope.target !== undefined) properties.push(`target ${scope.target}`);
  if (scope.virtualEntry !== undefined) properties.push(`virtual table entry ${scope.virtualEntry}`);
  return properties.join("; ");
};

export const codeViewScopeProperties = (record: LegacyCodeViewSymbol): string => {
  const scope = record.scope;
  if (!scope) return "scope fields unavailable";
  if (scope.kind === "inline") return inlineProperties(record).join("; ");
  if (scope.kind === "thunk") return thunkProperties(scope);
  return scope.kind === "with" ? "WITH expression" : "lexical block";
};
