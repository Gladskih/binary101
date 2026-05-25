"use strict";

import { toHex32 } from "../../binary-utils.js";
import { MACHINE } from "./constants.js";

type PeMachineOs = "Apple" | "FreeBSD" | "Linux" | "NetBSD" | "SunOS";

export interface DecodedPeMachine {
  rawMachine: number;
  machine: number;
  machineName: string;
  os: PeMachineOs | null;
}

// .NET runtime ReadyToRun encodes the target OS into IMAGE_FILE_HEADER.Machine by XOR.
// https://github.com/dotnet/runtime/blob/main/src/coreclr/inc/pedecoder.h
const READY_TO_RUN_OS_OVERRIDES: Array<[number, PeMachineOs]> = [
  [0x4644, "Apple"],
  [0xadc4, "FreeBSD"],
  [0x7b79, "Linux"],
  [0x1993, "NetBSD"],
  [0x1992, "SunOS"]
];

const machineName = (machine: number): string | null =>
  MACHINE.find(([code]) => code === (machine >>> 0))?.[1] || null;

const decodeReadyToRunMachine = (rawMachine: number): DecodedPeMachine | null => {
  for (const [override, os] of READY_TO_RUN_OS_OVERRIDES) {
    const machine = (rawMachine ^ override) & 0xffff;
    const name = machine === 0 ? null : machineName(machine);
    if (name) return { rawMachine, machine, machineName: name, os };
  }
  return null;
};

export const decodePeMachine = (machine: number): DecodedPeMachine => {
  const rawMachine = machine & 0xffff;
  const name = machineName(rawMachine);
  if (name) return { rawMachine, machine: rawMachine, machineName: name, os: null };
  return decodeReadyToRunMachine(rawMachine) || {
    rawMachine,
    machine: rawMachine,
    machineName: `machine=${toHex32(rawMachine, 4)}`,
    os: null
  };
};

export const getCanonicalPeMachine = (machine: number): number =>
  decodePeMachine(machine).machine;

export const isReadyToRunOsOverriddenMachine = (machine: number): boolean =>
  decodePeMachine(machine).os != null;

export const formatPeMachine = (machine: number): string => {
  const decoded = decodePeMachine(machine);
  return decoded.os
    ? `${decoded.machineName} ReadyToRun for ${decoded.os}`
    : decoded.machineName;
};

export const getPeMachineRenderOptions = (machine: number): Array<[number, string, string?]> => {
  const decoded = decodePeMachine(machine);
  if (!decoded.os) return MACHINE;
  return [
    ...MACHINE,
    [
      decoded.rawMachine,
      `${decoded.os} R2R ${decoded.machineName}`,
      `ReadyToRun Machine value: ${decoded.machineName} XOR ${decoded.os} OS override`
    ]
  ];
};
