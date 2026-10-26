import type { PeLegacyCodeViewInfo } from "../../analyzers/pe/debug/legacy-codeview.js";
import type { LegacyCodeViewSymbol } from "../../analyzers/pe/debug/legacy-codeview-symbol-records.js";
import { analyzeCodeViewLocalScopes, type CodeViewLocalBinding } from "../../analyzers/pe/debug/codeview-local-scopes.js";
import type { CodeViewLocalRange } from "../../analyzers/pe/debug/codeview-local-types.js";
import type { LegacyCodeViewTable } from "./legacy-codeview-tables.js";
import { codeViewFrameBase, codeViewFrameFlags, codeViewLocalFlags, codeViewLocalPlacement } from "./codeview-local-properties.js";

interface LocalTableState {
  frames: LegacyCodeViewTable;
  locals: LegacyCodeViewTable;
  counts: Map<string, number>;
  directory: number;
  module: number;
}

const increment = (state: LocalTableState, name: string): void => {
  state.counts.set(name, (state.counts.get(name) ?? 0) + 1);
};
const procedureName = (binding: CodeViewLocalBinding): string => binding.procedure?.name ?? "(scope unresolved)";

const gapBytes = (binding: CodeViewLocalBinding): bigint | undefined => {
  const range = binding.record.localRange!;
  if (!range.range && binding.record.type !== 0x1144) return undefined;
  let previousEnd = 0;
  let total = 0n;
  for (const gap of range.gaps) {
    if (!range.range || gap.offset < previousEnd || gap.offset + gap.length > range.range.length) return undefined;
    previousEnd = gap.offset + gap.length;
    total += BigInt(gap.length);
  }
  return total;
};

interface LocalRangeTotals { bytes: bigint | undefined; gaps: bigint | undefined; fullScope: boolean; }

const tallyRangeBytes = (totals: LocalRangeTotals, binding: CodeViewLocalBinding): void => {
  if (binding.record.type === 0x1144) { totals.fullScope = true; return; }
  const range = binding.record.localRange!.range;
  if (!range || range.length >= 0xf000) { totals.bytes = undefined; return; }
  if (totals.bytes !== undefined) totals.bytes += BigInt(range.length);
};

const rangeSummary = (ranges: readonly CodeViewLocalBinding[]): string[] => {
  const totals: LocalRangeTotals = { bytes: 0n, gaps: 0n, fullScope: false };
  for (const binding of ranges) {
    tallyRangeBytes(totals, binding);
    const count = gapBytes(binding);
    if (count === undefined) totals.gaps = undefined;
    else if (totals.gaps !== undefined) totals.gaps += count;
  }
  return [String(ranges.length), totals.bytes === undefined ? "unavailable"
    : `${totals.bytes}${totals.fullScope ? " + full scope" : ""}`,
  totals.gaps === undefined ? "invalid gap list" : String(totals.gaps)];
};

const rangeAttributes = (range: CodeViewLocalRange): string[] => {
  const attributes = range.attributes ?? 0;
  const result: string[] = [];
  const relative = range.location.kind === "registerRelative";
  if (attributes & 1) result.push(relative ? "spilled member" : "may have no name");
  if (relative && attributes >>> 4) result.push(`parent offset ${attributes >>> 4}`);
  const unknown = attributes & (relative ? 0xe : 0xfffe);
  if (unknown) result.push(`unknown attributes 0x${unknown.toString(16)}`);
  return result;
};

const rangePlacement = (binding: CodeViewLocalBinding, machine: number | undefined): string => {
  const range = binding.record.localRange!;
  const attributes = rangeAttributes(range);
  if (range.parentOffset !== undefined) attributes.push(`parent offset ${range.parentOffset}`);
  return [codeViewLocalPlacement(range.location, machine), ...attributes].join("; ");
};

const addLocal = (state: LocalTableState, binding: CodeViewLocalBinding, ranges: readonly CodeViewLocalBinding[],
  machine: number | undefined): void => {
  const local = binding.record.local!;
  const placements = local.location ? [codeViewLocalPlacement(local.location, machine)]
    : ranges.map(range => rangePlacement(range, machine));
  const issues = [...new Set([...binding.issues, ...ranges.flatMap(range => range.issues)])];
  state.locals.rows.push([binding.record.name ?? "(name unavailable)", procedureName(binding), `#${local.typeIndex}`,
    [...new Set(placements)].join("; ") || "not stored", codeViewLocalFlags(local.flags), ...rangeSummary(ranges),
    issues.join("; ") || "validated procedure scope", String(state.directory), String(state.module)]);
  increment(state, "Local variable descriptions");
  if ((local.flags ?? 0) & 1) increment(state, "Parameters");
  if ((local.flags ?? 0) & 0x100) increment(state, "Optimized-out variables");
};

const addFrame = (state: LocalTableState, binding: CodeViewLocalBinding, machine: number | undefined): void => {
  const frame = binding.record.frame!;
  const properties = [codeViewFrameFlags(frame.flags)];
  if (frame.paddingBytes) properties.push(`padding begins at stored frame offset ${frame.paddingOffset}`);
  if (frame.handler.section || frame.handler.offset) properties.push(`handler ${frame.handler.section}:${frame.handler.offset}`);
  state.frames.rows.push([procedureName(binding), String(frame.frameBytes), String(frame.paddingBytes),
    String(frame.savedRegisterBytes), codeViewFrameBase((frame.flags >>> 14) & 3, machine),
    codeViewFrameBase((frame.flags >>> 16) & 3, machine), properties.join("; "),
    binding.issues.join("; ") || "validated procedure scope", String(state.directory), String(state.module)]);
  increment(state, "Compiler frame descriptions");
};

const groupRange = (state: LocalTableState, ranges: Map<LegacyCodeViewSymbol, CodeViewLocalBinding[]>,
  binding: CodeViewLocalBinding): void => {
  if (!binding.record.localRange) return;
  increment(state, "Location range records");
  if (binding.local) {
    const values = ranges.get(binding.local) ?? [];
    values.push(binding);
    ranges.set(binding.local, values);
  } else increment(state, "Location ranges without a consecutive local");
};

const addBindings = (state: LocalTableState, bindings: readonly CodeViewLocalBinding[],
  machine: number | undefined): void => {
  const ranges = new Map<LegacyCodeViewSymbol, CodeViewLocalBinding[]>();
  for (const binding of bindings) {
    groupRange(state, ranges, binding);
    if (binding.issues.length) increment(state, "Metadata records with unresolved or invalid scopes");
    if (binding.record.frame) addFrame(state, binding, machine);
  }
  for (const binding of bindings) {
    if (binding.record.local) addLocal(state, binding, ranges.get(binding.record) ?? [], machine);
  }
};

/** Sum stored range descriptions, not unique live bytes across overlapping locations. */
export const buildCodeViewLocalTables = (info: PeLegacyCodeViewInfo, machine?: number): LegacyCodeViewTable[] => {
  const state: LocalTableState = {
    frames: { key: "compilerFrames", title: "Compiler frame descriptions", columns: ["Procedure", "Frame bytes",
      "Padding bytes", "Saved register bytes", "Local base", "Parameter base", "Properties", "Scope status",
      "Directory", "Module"], rows: [] },
    locals: { key: "localVariables", title: "Local variables and parameters", columns: ["Name", "Procedure", "Type reference",
      "Placement", "Properties", "Range records", "Declared range bytes (sum)", "Gap bytes (sum)", "Scope status",
      "Directory", "Module"], rows: [] },
    counts: new Map(), directory: 0, module: 0
  };
  for (const [index, directory] of info.directories.entries()) for (const section of directory.subsections) {
    const data = section.data;
    if (data?.kind !== "symbols" || data.encoding !== undefined) continue;
    state.directory = index + 1;
    state.module = section.module;
    const analysis = analyzeCodeViewLocalScopes(data);
    addBindings(state, analysis.bindings, machine);
    if (analysis.bindings.length) for (const issue of analysis.issues) increment(state, `Scope diagnostic: ${issue}`);
  }
  return [{ key: "localStatistics", title: "Frame and local metadata statistics", columns: ["Metadata", "Records"],
    rows: [...state.counts].map(([label, count]) => [label, String(count)]) }, state.frames, state.locals]
    .filter(table => table.rows.length);
};
