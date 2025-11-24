"use strict";

import { toHex32 } from "../../binary-utils.js";
import { MACHINE } from "./constants.js";
import type { PeDataDirectory } from "./types.js";

export const peProbe = (dataView: DataView): { e_lfanew: number } | null =>
  dataView.byteLength >= 0x40 && dataView.getUint16(0, true) === 0x5a4d
    ? { e_lfanew: dataView.getUint32(0x3c, true) }
    : null;

export const mapMachine = (machineCode: number): string =>
  MACHINE.find(([code]) => code === machineCode)?.[1] || `machine=${toHex32(machineCode, 4)}`;

export const findDataDirectory = (
  dataDirs: PeDataDirectory[],
  name: string
): PeDataDirectory | undefined => dataDirs.find(d => d.name === name);
