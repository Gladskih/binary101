export interface ArmntOpcodeStatistics {
  opcodeCounts: Record<string, number>;
  stackAdjustments: Record<number, number>;
  integerRegisterPopCount: number;
  floatingRegisterPopCount: number;
  framePointerRestores: number;
  returnAddressLoads: number;
  specialMarkers: Record<string, number>;
  incompleteSequenceCount: number;
}
