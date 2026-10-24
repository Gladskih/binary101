import type { Arm64DecodedUnwind, Arm64UnwindOperation, Arm64UnwindStatistics } from "./arm64-unwind-types.js";

export const createArm64UnwindStatistics = (): Arm64UnwindStatistics => ({
  blockCount: 0, incompleteBlockCount: 0, operationCounts: {}, registerCounts: {},
  allocationCounts: {}, preIndexAdjustmentCounts: {}, scalableAllocationCounts: {},
  saveOffsetCounts: {}, scalableSaveCounts: {}, frameOffsetCounts: {}
});

const increment = (counts: Record<string, number>, key: string | number): void => {
  counts[key] = (counts[key] ?? 0) + 1;
};

const recordOperation = (statistics: Arm64UnwindStatistics, operation: Arm64UnwindOperation): void => {
  increment(statistics.operationCounts, operation.opcode);
  if (operation.kind === "allocate") increment(operation.unit === "bytes"
    ? statistics.allocationCounts : statistics.scalableAllocationCounts, operation.amount);
  if (operation.kind === "frame") increment(statistics.frameOffsetCounts, operation.displacement);
  if (operation.kind !== "save") return;
  for (const name of operation.registers) increment(statistics.registerCounts, name);
  if (operation.unit !== "bytes") {
    increment(statistics.scalableSaveCounts, `${operation.unit}:${operation.displacement}`);
  } else if (operation.addressing === "preIndex") {
    increment(statistics.preIndexAdjustmentCounts, -operation.displacement);
  } else increment(statistics.saveOffsetCounts, operation.displacement);
};

/** Caller deduplicates shared/chained references by the decoded record's identity. */
export const recordArm64UnwindStatistics = (statistics: Arm64UnwindStatistics, record: Arm64DecodedUnwind): void => {
  statistics.blockCount++;
  if (record.hasDecodeGaps) statistics.incompleteBlockCount++;
  for (const operation of record.operations) recordOperation(statistics, operation);
};
