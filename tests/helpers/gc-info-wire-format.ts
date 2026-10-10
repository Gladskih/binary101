// Test-owned wire widths stay independent from the production decoder oracle.
// Bases follow GCInfoBitStreamReader; flags follow GcInfoHeaderFlags and decoder layout.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/inc/gcinfotypes.h
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/inc/gcinfodecoder.h
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/vm/gcinfodecoder.cpp
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/gcinfo/gcinfoencoder.cpp
// https://github.com/dotnet/runtime/tree/v10.0.0/src/coreclr/tools/aot/ILCompiler.Reflection.ReadyToRun/Amd64
export const GC_INFO_BASES = {
  headerFlags: 10, codeLength: 8, slimV3ReturnKind: 2, fatV3ReturnKind: 4,
  signedStackOffset: 6, stackBaseRegister: 3, editAndContinueBytes: 4,
  outgoingStackUnits: 3, safePointCount: 2, interruptibleRangeCount: 1,
  safePointPointerWidth: 3, transitionPointerWidth: 3, transitionOffset: 6,
  registerCount: 2, stackCount: 2, untrackedCount: 1, register: 3,
  registerDelta: 2, stackSlotOffset: 6, stackSlotDelta: 4
} as const;

export const GC_INFO_HEADER_FLAGS = {
  hasGsCookie: 0x004, hasPspSymbol: 0x008, genericsContextThis: 0x030,
  hasStackBaseRegister: 0x040, hasEditAndContinueInfo: 0x100,
  reversePInvokeFrame: 0x200
} as const;
