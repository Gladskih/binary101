"use strict";

import { formatPeMachine } from "../machine.js";
import type { PeDataDirectory } from "../types.js";

export const peProbe = (dataView: DataView): { e_lfanew: number } | null =>
  dataView.byteLength >= 0x40 && dataView.getUint16(0, true) === 0x5a4d
    ? { e_lfanew: dataView.getUint32(0x3c, true) }
    : null;

export const mapMachine = (machineCode: number): string =>
  formatPeMachine(machineCode);

export const findDataDirectory = (
  dataDirs: PeDataDirectory[],
  name: string
): PeDataDirectory | undefined => dataDirs.find(d => d.name === name);
