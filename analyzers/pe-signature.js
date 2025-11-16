"use strict";

import { toHex32 } from "../binary-utils.js";
import { MACHINE } from "./pe-constants.js";

export const peProbe = dataView =>
  dataView.byteLength >= 0x40 && dataView.getUint16(0, true) === 0x5a4d
    ? { e_lfanew: dataView.getUint32(0x3c, true) }
    : null;

export const mapMachine = machineCode =>
  MACHINE.find(([code]) => code === machineCode)?.[1] || "machine=" + toHex32(machineCode, 4);

