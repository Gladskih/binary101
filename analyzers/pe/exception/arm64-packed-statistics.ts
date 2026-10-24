import type { Arm64PackedStatistics } from "./arm64-packed-types.js";

// Microsoft ARM64 exception handling, "Packed unwind data".
// RegF=0 saves no FP registers; other RegF values encode RegF+1 registers.
// https://learn.microsoft.com/en-us/cpp/build/arm64-exception-handling#packed-unwind-data
export const createArm64PackedStatistics = (): Arm64PackedStatistics => ({
  frameSizeCounts: {}, registerCounts: {}, returnKinds: {}, homesParametersCount: 0, fragmentCount: 0
});

const increment = (counts: Record<string, number>, key: string | number): void => {
  counts[key] = (counts[key] ?? 0) + 1;
};

const recordRegisters = (statistics: Arm64PackedStatistics, word: number): void => {
  const integers = (word >>> 16) & 15;
  // Values above ten cannot name the documented X19-X28 register group.
  if (integers <= 10) {
    for (let index = 0; index < integers; index++) increment(statistics.registerCounts, `X${19 + index}`);
  }
  const floating = (word >>> 13) & 7;
  if (floating) {
    for (let index = 0; index <= floating; index++) increment(statistics.registerCounts, `D${8 + index}`);
  }
  const chain = (word >>> 21) & 3;
  if (chain) increment(statistics.registerCounts, "LR");
  if (chain >= 2) increment(statistics.registerCounts, "X29");
};

/** Packed entries describe frames individually, even when their encoded words match. */
export const recordArm64PackedStatistics = (statistics: Arm64PackedStatistics, word: number): void => {
  const flag = word & 3;
  if (flag === 0 || flag === 3) return;
  if (flag === 2) statistics.fragmentCount++;
  if (word & (1 << 20)) statistics.homesParametersCount++;
  increment(statistics.frameSizeCounts, word >>> 23 << 4);
  increment(statistics.returnKinds, (word >>> 21) & 3);
  recordRegisters(statistics, word);
};
