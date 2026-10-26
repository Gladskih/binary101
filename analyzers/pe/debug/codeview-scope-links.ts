import type { LegacyCodeViewSymbol } from "./legacy-codeview-symbol-records.js";

export const codeViewScopeLinks = (record: LegacyCodeViewSymbol) =>
  record.procedure?.scopeOffsets ?? record.scope?.scopeOffsets ?? record.data?.scopeOffsets;
export const codeViewScopeLocation = (record: LegacyCodeViewSymbol) =>
  record.procedure?.storedLocation ?? record.scope?.location ?? record.data?.location;
export const codeViewScopeLength = (record: LegacyCodeViewSymbol) =>
  record.procedure?.codeLength ?? record.scope?.codeLength ?? record.data?.codeLength;
export const isCodeViewCallable = (record: LegacyCodeViewSymbol): boolean =>
  Boolean(record.procedure || record.scope?.kind === "thunk");
export const codeViewScopeEndType = (record: LegacyCodeViewSymbol): number => {
  if (record.scope?.kind === "inline" || [0x114d, 0x115d].includes(record.type)) return 0x114e;
  return record.procedure?.referenceKind === "procedureId" ? 0x114f : 6;
};

const nextOffset = (record: LegacyCodeViewSymbol): number =>
  record.procedure?.scopeOffsets?.next ?? record.scope?.scopeOffsets?.next ?? 0;

// TIS 1.2: pNext chains outermost procedures AND thunks within one segment.
// No byte-order monotonicity is promised. Use a graph walk, not a forward-offset test.
// https://openwatcom.org/ftp/devel/docs/CodeView.pdf
const segmentIssue = (record: LegacyCodeViewSymbol, target: LegacyCodeViewSymbol): string | undefined => {
  const source = codeViewScopeLocation(record);
  const destination = codeViewScopeLocation(target);
  if (!source || !destination) return "Scope next chain has unavailable segment fields.";
  if (source.segment !== destination.segment) return "Scope next chain crosses segments.";
  return undefined;
};

const nextIssue = (record: LegacyCodeViewSymbol, target: LegacyCodeViewSymbol | undefined): string | undefined => {
  if (!target || target === record || !isCodeViewCallable(target)) return "Scope next link does not identify another procedure or thunk.";
  if (codeViewScopeLinks(record)?.parent !== 0 || codeViewScopeLinks(target)?.parent !== 0) {
    return "Scope next chain includes a non-outermost scope.";
  }
  return segmentIssue(record, target);
};

const walkChain = (start: LegacyCodeViewSymbol, edges: Map<LegacyCodeViewSymbol, LegacyCodeViewSymbol>,
  finished: Set<LegacyCodeViewSymbol>, cycles: Set<LegacyCodeViewSymbol>): void => {
  const path = new Set<LegacyCodeViewSymbol>();
  let cursor: LegacyCodeViewSymbol | undefined = start;
  while (cursor && !finished.has(cursor) && !path.has(cursor)) {
    path.add(cursor);
    cursor = edges.get(cursor);
  }
  const cyclic = cursor !== undefined && (path.has(cursor) || cycles.has(cursor));
  for (const record of path) {
    finished.add(record);
    if (cyclic) cycles.add(record);
  }
};

/** Linear-time validation of all pNext components, including tails that enter cycles. */
export const analyzeCodeViewScopeChains = (index: ReadonlyMap<number, LegacyCodeViewSymbol>
): Map<LegacyCodeViewSymbol, string> => {
  const issues = new Map<LegacyCodeViewSymbol, string>();
  const edges = new Map<LegacyCodeViewSymbol, LegacyCodeViewSymbol>();
  for (const record of index.values()) {
    const next = nextOffset(record);
    if (!next) continue;
    const target = index.get(next);
    const issue = nextIssue(record, target);
    if (issue) issues.set(record, issue);
    else edges.set(record, target!);
  }
  const finished = new Set<LegacyCodeViewSymbol>();
  const cycles = new Set<LegacyCodeViewSymbol>();
  for (const start of edges.keys()) if (!finished.has(start)) walkChain(start, edges, finished, cycles);
  for (const record of cycles) issues.set(record, "Scope next chain contains a cycle.");
  return issues;
};
