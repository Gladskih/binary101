import type { Amd64UnwindCodeAnalysis } from "./unwind-code-slots.js";
import type { Amd64UnwindOperation, Amd64UnwindV12Header, Amd64UnwindV12Statistics } from "./unwind-v12-types.js";

export const createV12Statistics = (): Amd64UnwindV12Statistics => ({
  blockCount: 0, incompleteBlockCount: 0, operationCounts: {}, registerCounts: {},
  allocationCounts: {}, saveOffsetCounts: {}, frameRegisterCounts: {}, frameOffsetCounts: {},
  machineFrameCounts: {}, prologSizeCounts: {}
});

const increment = (counts: Record<string, number>, key: string | number): void => {
  counts[key] = (counts[key] ?? 0) + 1;
};

const registerName = (register: number): string =>
  ["RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI"][register] ?? `R${register}`;

const recordOperation = (statistics: Amd64UnwindV12Statistics, operation: Amd64UnwindOperation): void => {
  increment(statistics.operationCounts, operation.opcode);
  if (operation.opcode === "ALLOC_SMALL" || operation.opcode === "ALLOC_LARGE") {
    increment(statistics.allocationCounts, operation.size);
  }
  if (operation.opcode === "PUSH_MACHFRAME") increment(statistics.machineFrameCounts, operation.size);
  if ("displacement" in operation) increment(statistics.saveOffsetCounts, operation.displacement);
  if ("register" in operation) increment(statistics.registerCounts, operation.opcode.startsWith("SAVE_XMM")
    ? `XMM${operation.register}` : registerName(operation.register));
};

/** Each unique referenced v1/v2 block contributes once, including decoded prefixes of bad blocks. */
export const recordV12Statistics = (statistics: Amd64UnwindV12Statistics,
  header: Amd64UnwindV12Header, analysis: Amd64UnwindCodeAnalysis): void => {
  statistics.blockCount++;
  if (analysis.isTruncated || analysis.issues.length) statistics.incompleteBlockCount++;
  increment(statistics.prologSizeCounts, header.prologSize);
  if (header.frameRegister) {
    increment(statistics.frameRegisterCounts, registerName(header.frameRegister));
    increment(statistics.frameOffsetCounts, header.frameOffset);
  }
  for (const operation of analysis.operations) recordOperation(statistics, operation);
};
