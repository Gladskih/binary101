"use strict";

import { createThinMachOFixtureState, planThinMachOFixture } from "./macho-thin-state.js";
import type { ThinMachOFixture } from "./macho-thin-types.js";
import { writeThinMachOFixture } from "./macho-thin-writer.js";

export const CPU_TYPE_X86_64 = 0x01000007;
export const CPU_TYPE_ARM64 = 0x0100000c;
export const CPU_SUBTYPE_X86_64_ALL = 3;
export const CPU_SUBTYPE_ARM64E = 2;

export const createThinMachOFixture = (
  cpuType: number,
  cpuSubtype: number,
  uuidTail: number,
  identifier: string
): ThinMachOFixture => {
  const plan = planThinMachOFixture(cpuType, identifier);
  const state = createThinMachOFixtureState(plan);
  writeThinMachOFixture(state, plan, cpuType, cpuSubtype, uuidTail);
  return { bytes: state.bytes, layout: state.layout };
};
