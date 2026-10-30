import type { Td32Symbols } from "./td32-symbols.js";
import type { Td32SymbolRecord } from "./td32-symbol-types.js";

export interface Td32ScopeLinks { parent?: Td32SymbolRecord; issues: string[]; }

/** Source offsets are subsection-relative, including the 4/32-byte stream header.
 * Delphi Win32 may emit nested procedures as top-level stream siblings: do not
 * require physical nesting or borrow CodeView's lexical-stack associations.
 * https://github.com/csm101/delphi-visual-studio-code-debugger/blob/580b258063a37e6e6bd93a9a7593e0b8cc8a9d06/docs/TD32_FORMAT_NOTES.md#nested-procedures-pparent-is-the-only-record-dcc32-emits--confirmed
 */
const walkCycle = (start: Td32SymbolRecord, edges: ReadonlyMap<Td32SymbolRecord, Td32SymbolRecord>,
  finished: Set<Td32SymbolRecord>, result: Set<Td32SymbolRecord>): void => {
    const path = new Set<Td32SymbolRecord>();
    let cursor: Td32SymbolRecord | undefined = start;
    while (cursor && !finished.has(cursor) && !path.has(cursor)) {
      path.add(cursor);
      cursor = edges.get(cursor);
    }
    const cyclic = cursor !== undefined && (path.has(cursor) || result.has(cursor));
    for (const record of path) {
      finished.add(record);
      if (cyclic) result.add(record);
    }
};

const cycles = (edges: ReadonlyMap<Td32SymbolRecord, Td32SymbolRecord>): Set<Td32SymbolRecord> => {
  const finished = new Set<Td32SymbolRecord>();
  const result = new Set<Td32SymbolRecord>();
  for (const start of edges.keys()) if (!finished.has(start)) walkCycle(start, edges, finished, result);
  return result;
};

const endIssue = (index: ReadonlyMap<number, Td32SymbolRecord>,
  record: Td32SymbolRecord, offset: number): string | undefined => {
  const end = record.metadata!.scopeOffsets!.end;
  if (end === 0) return "Scope end link is not populated.";
  if (end <= offset || index.get(end)?.type !== 6) return "Scope end link does not identify a following END record.";
  return undefined;
};

const segmentOf = (record: Td32SymbolRecord): number | undefined => record.metadata?.location?.segment;

const nextIssue = (record: Td32SymbolRecord, next: Td32SymbolRecord | undefined): string | undefined => {
  if (!next || ![0x204, 0x205, 0x206].includes(next.type)) return "Scope next link does not identify a procedure or thunk.";
  if (!next.metadata?.scopeOffsets) return "Scope next target has unavailable scope fields.";
  const segment = segmentOf(record);
  const nextSegment = segmentOf(next);
  if (segment === undefined || nextSegment === undefined) return "Scope next target has unavailable segment fields.";
  if (segment !== nextSegment) return "Scope next link crosses segments.";
  return undefined;
};

const checkRecord = (index: ReadonlyMap<number, Td32SymbolRecord>, record: Td32SymbolRecord,
  offset: number): Td32ScopeLinks => {
  const result: Td32ScopeLinks = { issues: [] };
  const scope = record.metadata!.scopeOffsets!;
  const issue = endIssue(index, record, offset);
  if (issue) result.issues.push(issue);
  if (scope.parent !== 0) {
    const parent = index.get(scope.parent);
    if (parent?.metadata?.scopeOffsets) result.parent = parent;
    else result.issues.push("Scope parent link does not identify a decoded scope.");
  }
  if (scope.next) {
    const next = nextIssue(record, index.get(scope.next));
    if (next) result.issues.push(next);
  }
  return result;
};

const validOffsets = (data: Td32Symbols): boolean => data.recordOffsets !== undefined
  && data.recordOffsets.length === data.records.length && data.recordOffsets.every((offset, index, offsets) =>
    Number.isSafeInteger(offset) && offset >= 0 && (index === 0 || offset > offsets[index - 1]!));

const scopeGraph = (index: ReadonlyMap<number, Td32SymbolRecord>) => {
  const result = new Map<Td32SymbolRecord, Td32ScopeLinks>();
  const parents = new Map<Td32SymbolRecord, Td32SymbolRecord>();
  const next = new Map<Td32SymbolRecord, Td32SymbolRecord>();
  for (const [offset, record] of index) {
    if (!record.metadata?.scopeOffsets) continue;
    const links = checkRecord(index, record, offset);
    result.set(record, links);
    if (links.parent) parents.set(record, links.parent);
    const nextOffset = record.metadata.scopeOffsets.next;
    const target = nextOffset ? index.get(nextOffset) : undefined;
    if (target?.metadata?.scopeOffsets) next.set(record, target);
  }
  return { result, parents, next };
};

export const analyzeTd32SymbolLinks = (data: Td32Symbols): Map<Td32SymbolRecord, Td32ScopeLinks> => {
  const scoped = data.records.filter(record => record.metadata?.scopeOffsets);
  if (!validOffsets(data)) return new Map(scoped.map(record => [record,
    { issues: ["Physical symbol offsets are unavailable or invalid; scope links are unresolved."] }]));
  const index = new Map(data.records.map((record, position) => [data.recordOffsets![position]!, record]));
  const { result, parents, next } = scopeGraph(index);
  for (const record of cycles(parents)) {
    result.get(record)!.issues.push("Scope parent cycle.");
    delete result.get(record)!.parent;
  }
  for (const record of cycles(next)) result.get(record)!.issues.push("Scope next cycle.");
  return result;
};
