export interface Arm64PackedStatistics {
  frameSizeCounts: Record<number, number>;
  registerCounts: Record<string, number>;
  returnKinds: Record<number, number>;
  homesParametersCount: number;
  fragmentCount: number;
}
