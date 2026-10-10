export interface ManagedGcHeader {
  flags: number;
  codeLength: number;
  returnKind?: number;
  validRange?: { startOffset: number; endOffset: number };
  cookieStackOffset?: number;
  parentStackOffset?: number;
  genericContextStackOffset?: number;
  stackBaseRegister?: number;
  editAndContinueBytes?: number;
  reversePInvokeStackOffset?: number;
  outgoingStackBytes?: number;
}

export type ManagedGcSlot = { flags: number } & (
  | { kind: "register"; register: number }
  | { kind: "stack"; base: number; offset: number }
);

export interface ManagedGcInfo {
  header: ManagedGcHeader;
  safePoints: { offset: number; liveSlots: number[] }[];
  interruptibleRanges: { startOffset: number; endOffset: number }[];
  slots: ManagedGcSlot[];
  transitions: { offset: number; slot: number; live: boolean }[];
  warnings?: string[];
}

export interface NativeAotMethodGcMaps {
  methods: { startRva: number; info: ManagedGcInfo }[];
  warnings: string[];
}
