"use strict";

type MachOIncidentalValues = {
  nextBigUint64: () => bigint;
  nextLabel: (prefix: string) => string;
  nextUint16: () => number;
  nextUint32: () => number;
  nextUint8: () => number;
};

// Generates distinct filler values for tests where the exact scalar is not
// semantically important, while keeping the call sites deterministic.
const createMachOIncidentalValues = (start = 0): MachOIncidentalValues => {
  let current = start >>> 0;
  const nextUint32 = (): number => {
    current = (current + 1) >>> 0;
    return current;
  };
  return {
    nextBigUint64: () => (BigInt(nextUint32()) << 32n) | BigInt(nextUint32()),
    nextLabel: (prefix: string) => `${prefix}-${nextUint32().toString(16)}`,
    nextUint16: () => nextUint32() & 0xffff,
    nextUint32,
    nextUint8: () => nextUint32() & 0xff
  };
};

const packMachOVersion = (major: number, minor = 0, patch = 0): number =>
  (((major & 0xffff) << 16) | ((minor & 0xff) << 8) | (patch & 0xff)) >>> 0;

export { createMachOIncidentalValues, packMachOVersion };
