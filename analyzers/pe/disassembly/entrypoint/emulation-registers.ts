"use strict";

import type { IcedModule } from "./iced.js";

/**
 * Canonical general-purpose registers modeled by the entrypoint micro-emulator.
 *
 * This is intentionally not the full CPU register file: RIP, RFLAGS, segment,
 * vector, x87, MMX, control, debug, and model-specific registers are outside the
 * current state model. The list follows Intel SDM Vol. 1, section 3.4.1.1
 * "General-Purpose Registers in 64-Bit Mode".
 * https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
 */
export type CanonicalRegister =
  | "RAX"
  | "RBX"
  | "RCX"
  | "RDX"
  | "RSI"
  | "RDI"
  | "RBP"
  | "RSP"
  | "R8"
  | "R9"
  | "R10"
  | "R11"
  | "R12"
  | "R13"
  | "R14"
  | "R15";

export type RegisterAccess = {
  canonical: CanonicalRegister;
  accessBits: 8 | 16 | 32 | 64;
  bitOffset: 0 | 8;
};

type RegisterAlias = {
  canonical: CanonicalRegister;
  names: readonly string[];
  accessBits: RegisterAccess["accessBits"];
  bitOffset?: RegisterAccess["bitOffset"];
};

/**
 * General-purpose register aliases understood by the entrypoint micro-emulator.
 *
 * The alias groups and the x64 zero-extension rule follow Intel SDM Vol. 1,
 * section 3.4.1.1 "General-Purpose Registers in 64-Bit Mode".
 * https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
 *
 * 8-bit and 16-bit aliases include their bit offset so the state layer can
 * preserve the unaffected bits when the canonical register value is known.
 */
const ALIASES: readonly RegisterAlias[] = [
  { canonical: "RAX", names: ["RAX"], accessBits: 64 },
  { canonical: "RAX", names: ["EAX"], accessBits: 32 },
  { canonical: "RAX", names: ["AX"], accessBits: 16 },
  { canonical: "RAX", names: ["AL"], accessBits: 8 },
  { canonical: "RAX", names: ["AH"], accessBits: 8, bitOffset: 8 },
  { canonical: "RBX", names: ["RBX"], accessBits: 64 },
  { canonical: "RBX", names: ["EBX"], accessBits: 32 },
  { canonical: "RBX", names: ["BX"], accessBits: 16 },
  { canonical: "RBX", names: ["BL"], accessBits: 8 },
  { canonical: "RBX", names: ["BH"], accessBits: 8, bitOffset: 8 },
  { canonical: "RCX", names: ["RCX"], accessBits: 64 },
  { canonical: "RCX", names: ["ECX"], accessBits: 32 },
  { canonical: "RCX", names: ["CX"], accessBits: 16 },
  { canonical: "RCX", names: ["CL"], accessBits: 8 },
  { canonical: "RCX", names: ["CH"], accessBits: 8, bitOffset: 8 },
  { canonical: "RDX", names: ["RDX"], accessBits: 64 },
  { canonical: "RDX", names: ["EDX"], accessBits: 32 },
  { canonical: "RDX", names: ["DX"], accessBits: 16 },
  { canonical: "RDX", names: ["DL"], accessBits: 8 },
  { canonical: "RDX", names: ["DH"], accessBits: 8, bitOffset: 8 },
  { canonical: "RSI", names: ["RSI"], accessBits: 64 },
  { canonical: "RSI", names: ["ESI"], accessBits: 32 },
  { canonical: "RSI", names: ["SI"], accessBits: 16 },
  { canonical: "RSI", names: ["SIL"], accessBits: 8 },
  { canonical: "RDI", names: ["RDI"], accessBits: 64 },
  { canonical: "RDI", names: ["EDI"], accessBits: 32 },
  { canonical: "RDI", names: ["DI"], accessBits: 16 },
  { canonical: "RDI", names: ["DIL"], accessBits: 8 },
  { canonical: "RBP", names: ["RBP"], accessBits: 64 },
  { canonical: "RBP", names: ["EBP"], accessBits: 32 },
  { canonical: "RBP", names: ["BP"], accessBits: 16 },
  { canonical: "RBP", names: ["BPL"], accessBits: 8 },
  { canonical: "RSP", names: ["RSP"], accessBits: 64 },
  { canonical: "RSP", names: ["ESP"], accessBits: 32 },
  { canonical: "RSP", names: ["SP"], accessBits: 16 },
  { canonical: "RSP", names: ["SPL"], accessBits: 8 },
  { canonical: "R8", names: ["R8"], accessBits: 64 },
  { canonical: "R8", names: ["R8D"], accessBits: 32 },
  { canonical: "R8", names: ["R8W"], accessBits: 16 },
  { canonical: "R8", names: ["R8L"], accessBits: 8 },
  { canonical: "R9", names: ["R9"], accessBits: 64 },
  { canonical: "R9", names: ["R9D"], accessBits: 32 },
  { canonical: "R9", names: ["R9W"], accessBits: 16 },
  { canonical: "R9", names: ["R9L"], accessBits: 8 },
  { canonical: "R10", names: ["R10"], accessBits: 64 },
  { canonical: "R10", names: ["R10D"], accessBits: 32 },
  { canonical: "R10", names: ["R10W"], accessBits: 16 },
  { canonical: "R10", names: ["R10L"], accessBits: 8 },
  { canonical: "R11", names: ["R11"], accessBits: 64 },
  { canonical: "R11", names: ["R11D"], accessBits: 32 },
  { canonical: "R11", names: ["R11W"], accessBits: 16 },
  { canonical: "R11", names: ["R11L"], accessBits: 8 },
  { canonical: "R12", names: ["R12"], accessBits: 64 },
  { canonical: "R12", names: ["R12D"], accessBits: 32 },
  { canonical: "R12", names: ["R12W"], accessBits: 16 },
  { canonical: "R12", names: ["R12L"], accessBits: 8 },
  { canonical: "R13", names: ["R13"], accessBits: 64 },
  { canonical: "R13", names: ["R13D"], accessBits: 32 },
  { canonical: "R13", names: ["R13W"], accessBits: 16 },
  { canonical: "R13", names: ["R13L"], accessBits: 8 },
  { canonical: "R14", names: ["R14"], accessBits: 64 },
  { canonical: "R14", names: ["R14D"], accessBits: 32 },
  { canonical: "R14", names: ["R14W"], accessBits: 16 },
  { canonical: "R14", names: ["R14L"], accessBits: 8 },
  { canonical: "R15", names: ["R15"], accessBits: 64 },
  { canonical: "R15", names: ["R15D"], accessBits: 32 },
  { canonical: "R15", names: ["R15W"], accessBits: 16 },
  { canonical: "R15", names: ["R15L"], accessBits: 8 }
];

export const resolveRegister = (
  iced: IcedModule,
  register: number
): RegisterAccess | null => {
  if (!iced.Register) return null;
  for (const alias of ALIASES) {
    if (alias.names.some(name => iced.Register?.[name] === register)) {
      return {
        canonical: alias.canonical,
        accessBits: alias.accessBits,
        bitOffset: alias.bitOffset ?? 0
      };
    }
  }
  return null;
};
