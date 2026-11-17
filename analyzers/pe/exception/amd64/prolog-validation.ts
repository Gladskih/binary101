import type * as Iced from "iced-x86-disasm";
import type { FileRangeReader } from "../../../file-range-reader.js";
import type { RvaToOffset } from "../../types.js";
import type { Amd64RuntimeFunctionTable } from "./runtime-function-table.js";
import { Amd64PrologChecker } from "./prolog-check.js";
import { createAmd64UnwindBlockReader } from "./unwind-block-reader.js";
import type { Amd64PrologDescription, Amd64PrologCheck, Amd64PrologReport } from "./prolog-types.js";
import { orderedAmd64PrologRanges } from "./prolog-worklist.js";

type PendingDescription = { description: Amd64PrologDescription; cache: Map<string, Amd64PrologCheck> };

const recordCheck = (report: Amd64PrologReport, check: Amd64PrologCheck,
  beginRva: number, endRva: number, unwindInfoRva: number): void => {
  if (check.issues.length) report.findings.push({ beginRva, endRva, unwindInfoRva, ...check });
  else if (check.limitations.length) {
    const reason = check.limitations[0]!;
    report.unverifiedCounts[reason] = (report.unverifiedCounts[reason] ?? 0) + 1;
  } else report.matchedCount++;
};

/** Consume the existing unwind scan; neither the table nor the code slots are decoded twice. */
export const createAmd64PrologValidator = async (
  reader: FileRangeReader, rvaToOff: RvaToOffset,
  owners: Amd64RuntimeFunctionTable["functionsByUnwindRva"],
  loadIced: () => Promise<typeof Iced> = () => import("iced-x86-disasm")
) => {
  const report: Amd64PrologReport = { matchedCount: 0, unverifiedCounts: {}, findings: [] };
  const checker = new Amd64PrologChecker(await loadIced());
  const readCode = createAmd64UnwindBlockReader(reader, rvaToOff);
  const pending = new Map<number, PendingDescription>();
  let memoizedCount = 0;
  let pendingOperationCount = 0;
  const validate = async (begin: number, end: number, description: Amd64PrologDescription,
    cache: Map<string, Amd64PrologCheck>)
    : Promise<Amd64PrologCheck> => {
    if (description.prologSize > end - begin) {
      return { issues: [{ code: "prolog-size", offset: description.prologSize,
        expected: `at most ${end - begin} bytes` }], limitations: [] };
    }
    let view: DataView;
    try {
      const pending = readCode(begin);
      view = pending instanceof DataView ? pending : await pending;
    } catch { return { issues: [], limitations: ["code-read-failed"] }; }
    // Include a bounded epilog lookahead without crossing the function. 64 is a
    // scheduling budget, not a format limit: exhausted lookahead stays unverified.
    const bytes = new Uint8Array(view.buffer, view.byteOffset,
      Math.min(view.byteLength, end - begin, description.prologSize + 64));
    const key = String.fromCharCode(...bytes.subarray(0, description.prologSize));
    const cached = cache.get(key);
    if (cached) return cached;
    const check = checker.check(bytes, description, begin, end);
    // Only complete instruction boundaries depend exclusively on the prolog prefix.
    // A capped per-description memo saves repeated compiler templates without
    // retaining code for the whole image (measured on the Windows corpus).
    if (check.issues.length === 0 && check.limitations.length === 0) {
      // One batch-wide memo budget, independent of the number of descriptions.
      if (memoizedCount >= 4096) {
        for (const work of pending.values()) work.cache.clear();
        memoizedCount = 0;
      }
      cache.set(key, check);
      memoizedCount++;
    }
    return check;
  };
  const finish = async (): Promise<void> => {
    const groups = new Map([...pending.keys()].map(rva => [rva, owners.get(rva) ?? []]));
    for (const { rva, range } of orderedAmd64PrologRanges(groups)) {
      const work = pending.get(rva)!;
      recordCheck(report, await validate(range.begin, range.end, work.description, work.cache),
        range.begin, range.end, rva);
    }
    pending.clear();
    memoizedCount = 0;
    pendingOperationCount = 0;
  };
  return {
    report,
    finish,
    free: (): void => { pending.clear(); checker.free(); },
    observe: async (rva: number, description: Amd64PrologDescription): Promise<void> => {
      const ranges = owners.get(rva) ?? [];
      if (!ranges.length) return;
      const preflight = checker.check(new Uint8Array(), description);
      if (preflight.limitations[0] !== "unreadable-code") {
        for (const range of ranges) recordCheck(report, preflight, range.begin, range.end, rva);
        return;
      }
      pending.set(rva, { description, cache: new Map() });
      pendingOperationCount += description.operations.length + 1;
      // A measured budget of 8192 operation/description records improves code-read
      // locality while bounding retained metadata, including dense malformed blocks.
      // This is a scheduling budget, not a file-format cap.
      if (pendingOperationCount >= 8192) await finish();
    }
  };
};
