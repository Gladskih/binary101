import type { LegacyCodeViewSymbols } from "./legacy-codeview-symbols.js";
import type { LegacyCodeViewSymbol } from "./legacy-codeview-symbol-records.js";
import type { CodeViewLocalRange } from "./codeview-local-types.js";
import type { LegacyCodeViewProcedure } from "./legacy-codeview-procedure-symbols.js";

export interface CodeViewLocalBinding {
  record: LegacyCodeViewSymbol;
  procedure?: LegacyCodeViewSymbol;
  local?: LegacyCodeViewSymbol;
  issues: string[];
}
export interface CodeViewLocalScopeAnalysis { bindings: CodeViewLocalBinding[]; issues: string[]; }
interface ActiveScope {
  offset: number;
  end?: number;
  procedure?: LegacyCodeViewSymbol;
  issue?: string;
  closingType: number;
}
interface ScopeState {
  index: Map<number, LegacyCodeViewSymbol>;
  active: ActiveScope[];
  local?: LegacyCodeViewSymbol;
  result: CodeViewLocalScopeAnalysis;
}

const links = (record: LegacyCodeViewSymbol) => record.procedure?.scopeOffsets ?? record.data?.scopeOffsets;
const isScope = (record: LegacyCodeViewSymbol): boolean => record.procedure !== undefined || record.data?.kind === "block";
const metadata = (record: LegacyCodeViewSymbol): boolean => Boolean(record.frame || record.local || record.localRange);
type ScopeLinks = NonNullable<ReturnType<typeof links>>;
const scopeEndType = (record: LegacyCodeViewSymbol): number =>
  record.procedure?.referenceKind === "procedureId" ? 0x114f : 6;

// TIS 1.2: offsets are relative to this module's symbol table. Compiler output
// may legitimately leave links zero; CVPACK fills them. Never borrow another module.
// https://openwatcom.org/ftp/devel/docs/CodeView.pdf
const scopeEndIssue = (state: ScopeState, offset: number, scope: ScopeLinks, endType: number): string | undefined => {
  if (!scope.end) return "Scope links are not populated; lexical association is unresolved.";
  const end = state.index.get(scope.end);
  if (scope.end <= offset || !end || end.type !== endType) return "Scope link does not identify a matching end record.";
  return undefined;
};

const scopeParentIssue = (state: ScopeState, scope: ScopeLinks): string | undefined => {
  const parent = state.active.at(-1);
  if (scope.parent !== (parent?.offset ?? 0)) return "Scope parent link does not match its lexical parent.";
  if (parent?.end !== undefined && scope.end >= parent.end) return "Scope extends outside its lexical parent.";
  if (parent?.issue) return "Containing scope has unresolved links.";
  return undefined;
};

const scopeNextIssue = (state: ScopeState, record: LegacyCodeViewSymbol): string | undefined => {
  const scope = record.procedure?.scopeOffsets;
  const next = scope?.next;
  if (next && (state.index.get(next) === record || !state.index.get(next)?.procedure)) {
    return "Scope next link does not identify another procedure.";
  }
  return undefined;
};

const scopeLinkIssue = (state: ScopeState, offset: number, record: LegacyCodeViewSymbol): string | undefined => {
  const scope = links(record);
  if (!scope) return "Scope links are not populated; lexical association is unresolved.";
  return scopeEndIssue(state, offset, scope, scopeEndType(record))
    ?? scopeParentIssue(state, scope) ?? scopeNextIssue(state, record);
};

const createActiveScope = (state: ScopeState, offset: number, record: LegacyCodeViewSymbol,
  issue: string | undefined): ActiveScope => {
  const active: ActiveScope = { offset, closingType: scopeEndType(record) };
  const end = links(record)?.end;
  if (end) active.end = end;
  if (issue) active.issue = issue;
  else {
    const procedure = record.procedure ? record : state.active.at(-1)?.procedure;
    if (procedure) active.procedure = procedure;
  }
  return active;
};

const openScope = (state: ScopeState, offset: number, record: LegacyCodeViewSymbol): void => {
  if (record.procedure && links(record)?.parent === 0 && state.active.length) {
    state.result.issues.push("A new root procedure starts before the preceding scope closes.");
    state.active.length = 0;
  }
  const issue = scopeLinkIssue(state, offset, record);
  state.active.push(createActiveScope(state, offset, record, issue));
  if (issue) state.result.issues.push(issue);
  delete state.local;
};

const rangeBoundsIssue = (range: NonNullable<CodeViewLocalRange["range"]>,
  location: NonNullable<LegacyCodeViewProcedure["storedLocation"]>, length: number): string | undefined => {
  if (range.section !== location.segment) return "Local range segment differs from the containing procedure.";
  if (range.offset < location.offset || range.length > length - (range.offset - location.offset)) {
    return "Local live range lies outside the containing procedure.";
  }
  return undefined;
};

const rangeIssue = (range: CodeViewLocalRange["range"],
  procedure: LegacyCodeViewProcedure | undefined): string | undefined => {
  if (!range) return undefined;
  if (range.length >= 0xf000) return "Reserved local-range length encoding is not interpreted.";
  const location = procedure?.storedLocation;
  const length = procedure?.codeLength;
  if (!location) return "Procedure address fields are unavailable for range validation.";
  if (length === undefined) return "Procedure address fields are unavailable for range validation.";
  return rangeBoundsIssue(range, location, length);
};

const bindingScopeIssue = (scope: ActiveScope | undefined): string | undefined =>
  scope?.issue ?? (scope?.procedure ? undefined : "No validated containing procedure.");

const associateRange = (binding: CodeViewLocalBinding, local: LegacyCodeViewSymbol | undefined): void => {
  if (!binding.record.localRange) return;
  if (local) binding.local = local;
  else binding.issues.push("Local range has no consecutive S_LOCAL record.");
  if ((local?.local?.flags ?? 0) & 0x100) binding.issues.push("A location range follows an optimized-out local.");
};

const bindMetadata = (state: ScopeState, record: LegacyCodeViewSymbol): void => {
  const scope = state.active.at(-1);
  const issues: string[] = [];
  const scopeIssue = bindingScopeIssue(scope);
  if (scopeIssue) issues.push(scopeIssue);
  const binding: CodeViewLocalBinding = { record, issues };
  if (scope?.procedure) {
    binding.procedure = scope.procedure;
    const issue = rangeIssue(record.localRange?.range, scope.procedure.procedure);
    if (issue) issues.push(issue);
  }
  associateRange(binding, state.local);
  state.result.bindings.push(binding);
};

const closeScope = (state: ScopeState, offset: number, type: number): void => {
  const scope = state.active.pop();
  if (!scope) state.result.issues.push("Scope end has no matching opening record.");
  else if (scope.closingType !== type) state.result.issues.push("Scope closing record has the wrong kind.");
  else if (scope.end !== undefined && scope.end !== offset) state.result.issues.push("Scope closes at a different offset from its end link.");
  delete state.local;
};

const processRecord = (state: ScopeState, offset: number, record: LegacyCodeViewSymbol): void => {
  if (isScope(record)) { openScope(state, offset, record); return; }
  // Inline sites, thunks and WITH scopes need their own body/link decoders.
  // Keep their metadata visible without attributing it to the outer procedure.
  if ([0x114d, 0x115d, 0x1102, 0x0206, 0x0106, 0x1104, 0x0208, 0x0108].includes(record.type)) {
    state.active.push({ offset, issue: "Unsupported enclosing scope kind.",
      closingType: [0x114d, 0x115d].includes(record.type) ? 0x114e : 6 });
    delete state.local;
    return;
  }
  if ([6, 0x114e, 0x114f].includes(record.type)) { closeScope(state, offset, record.type); return; }
  if (record.local && record.type === 0x113e) state.local = record;
  else if (!record.localRange) delete state.local;
  if (metadata(record)) bindMetadata(state, record);
};

const validOffsets = (data: LegacyCodeViewSymbols): boolean => {
  const offsets = data.recordOffsets;
  return offsets !== undefined && offsets.length === data.records.length && offsets.every((offset, index) =>
    Number.isSafeInteger(offset) && offset >= 0 && (index === 0 || offset > offsets[index - 1]!));
};

/** Transient associations; source records retain only their stored fields and physical offsets. */
export const analyzeCodeViewLocalScopes = (data: LegacyCodeViewSymbols): CodeViewLocalScopeAnalysis => {
  const result: CodeViewLocalScopeAnalysis = { bindings: [], issues: [] };
  if (!validOffsets(data)) {
    const issue = "Physical symbol offsets are unavailable or invalid; lexical association is unresolved.";
    return { bindings: data.records.filter(metadata).map(record => ({ record, issues: [issue] })), issues: [issue] };
  }
  const offsets = data.recordOffsets!;
  const state: ScopeState = { index: new Map(), active: [], result };
  data.records.forEach((record, index) => state.index.set(offsets[index]!, record));
  data.records.forEach((record, index) => processRecord(state, offsets[index]!, record));
  if (state.active.length) result.issues.push("Symbol stream ends with unclosed lexical scopes.");
  return result;
};
