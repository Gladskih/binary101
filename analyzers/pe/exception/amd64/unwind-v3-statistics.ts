import type { Amd64UnwindV3, Amd64UnwindV3Statistics, Amd64WindingOperation } from "./unwind-v3-types.js";

export const createV3Statistics = (): Amd64UnwindV3Statistics => ({
  blockCount: 0,
  epilogCount: 0,
  inheritedEpilogCount: 0,
  largePrologCount: 0,
  largeEpilogCount: 0,
  prologSizeCounts: {},
  operationCounts: {},
  registerCounts: {},
  allocationCounts: {},
  canonicalFrameTypeCounts: {}
});

const increment = <Key extends string | number>(counts: Partial<Record<Key, number>>, key: Key): void => {
  counts[key] = (counts[key] ?? 0) + 1;
};

// AMD64 integer register numbering, including APX R16-R31.
// https://learn.microsoft.com/en-us/cpp/build/x64-unwind-information-v3#wod_push---1-byte
const generalRegisterName = (register: number): string => register < 8
  ? ["RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI"][register]!
  : `R${register}`;

const recordRegisters = (statistics: Amd64UnwindV3Statistics, operation: Amd64WindingOperation): void => {
  if (!("register" in operation)) return;
  increment(statistics.registerCounts, operation.opcode.startsWith("SAVE_XMM")
    ? `XMM${operation.register}` : generalRegisterName(operation.register));
  if (operation.opcode === "PUSH2") increment(statistics.registerCounts, generalRegisterName(operation.register2));
  if (operation.opcode === "PUSH_CONSECUTIVE_2") {
    increment(statistics.registerCounts, generalRegisterName(operation.register + 1));
  }
};

const recordOperation = (statistics: Amd64UnwindV3Statistics, operation: Amd64WindingOperation): void => {
  increment(statistics.operationCounts, operation.opcode);
  if ("size" in operation) increment(statistics.allocationCounts, operation.size);
  if ("frameType" in operation) increment(statistics.canonicalFrameTypeCounts, operation.frameType);
  recordRegisters(statistics, operation);
};

/** Inventory distinct referenced pool records, rather than counting shared epilog references again. */
// Microsoft V3 header LARGE is flag 0x08; EPILOG_INFO_LARGE is flag 0x02.
// https://learn.microsoft.com/en-us/cpp/build/x64-unwind-information-v3
export const recordV3Statistics = (statistics: Amd64UnwindV3Statistics, record: Amd64UnwindV3 | null): void => {
  statistics.blockCount += 1;
  if (!record) return;
  increment(statistics.prologSizeCounts, record.prologSize);
  if ((record.flags & 8) !== 0) statistics.largePrologCount += 1;
  const operations = new Set(record.prologOperations);
  statistics.epilogCount += record.epilogs.length;
  for (const epilog of record.epilogs) {
    if ((epilog.flags & 2) !== 0) statistics.largeEpilogCount += 1;
    if (epilog.kind === "inherited") statistics.inheritedEpilogCount += 1;
    else for (const operation of epilog.operations) operations.add(operation);
  }
  for (const operation of operations) recordOperation(statistics, operation);
};
