export interface ArmntPackedStatistics {
  returnKinds: Record<"popPc" | "branch16" | "branch32" | "noEpilog", number>;
  registerGroups: Record<string, number>;
  stackAdjustments: Record<number, number>;
  homesParametersCount: number;
  savesLinkRegisterCount: number;
  frameChainCount: number;
  prologFoldingCount: number;
  epilogFoldingCount: number;
}
