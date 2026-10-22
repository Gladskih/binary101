import type { ArmntPackedStatistics } from "./armnt-packed-types.js";

// Microsoft ARM packed unwind fields, including the 12 folded-adjustment encodings.
// https://learn.microsoft.com/en-us/cpp/build/arm-exception-handling#packed-unwind-data
export const createArmntPackedStatistics = (): ArmntPackedStatistics => ({
  returnKinds: { popPc: 0, branch16: 0, branch32: 0, noEpilog: 0 },
  registerGroups: {}, stackAdjustments: {}, homesParametersCount: 0, savesLinkRegisterCount: 0,
  frameChainCount: 0, prologFoldingCount: 0, epilogFoldingCount: 0
});

const increment = (counts: Record<string, number>, key: string | number): void => {
  counts[key] = (counts[key] ?? 0) + 1;
};

const registerGroup = (word: number): string => {
  const register = (word >>> 16) & 7;
  if ((word & (1 << 19)) === 0) return register === 0 ? "r4" : `r4-r${4 + register}`;
  if (register === 7) return "None";
  return register === 0 ? "d8" : `d8-d${8 + register}`;
};

const recordAdjustment = (statistics: ArmntPackedStatistics, adjustment: number): void => {
  if (adjustment >= 0x3f4) {
    increment(statistics.stackAdjustments, ((adjustment & 3) + 1) * 4);
    if ((adjustment & 4) !== 0) statistics.prologFoldingCount += 1;
    if ((adjustment & 8) !== 0) statistics.epilogFoldingCount += 1;
  } else increment(statistics.stackAdjustments, adjustment * 4);
};

export const recordArmntPackedStatistics = (statistics: ArmntPackedStatistics, word: number): void => {
  const flag = word & 3;
  if (flag === 0 || flag === 3) return;
  increment(statistics.returnKinds, (["popPc", "branch16", "branch32", "noEpilog"] as const)[(word >>> 13) & 3]!);
  increment(statistics.registerGroups, registerGroup(word));
  if ((word & (1 << 15)) !== 0) statistics.homesParametersCount += 1;
  if ((word & (1 << 20)) !== 0) statistics.savesLinkRegisterCount += 1;
  if ((word & (1 << 21)) !== 0) statistics.frameChainCount += 1;
  recordAdjustment(statistics, word >>> 22);
};
