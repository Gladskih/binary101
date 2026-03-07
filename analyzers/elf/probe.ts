"use strict";

const probeElf = (dv: DataView): string | null => {
  if (dv.byteLength < 0x14) return null;
  if (dv.getUint32(0, false) !== 0x7f454c46) return null;
  const classByte = dv.getUint8(4);
  const dataByte = dv.getUint8(5);
  const littleEndian = dataByte === 1;
  const type = dv.getUint16(0x10, littleEndian);
  const machine = dv.getUint16(0x12, littleEndian);
  const bitness = classByte === 1 ? "32-bit" : classByte === 2 ? "64-bit" : "?";
  const endian = dataByte === 1 ? "LSB" : dataByte === 2 ? "MSB" : "?";
  const machineLabel =
    machine === 0x3e
      ? "x86-64"
      : machine === 0x03
        ? "x86"
        : machine === 0xb7
          ? "ARM64"
          : machine === 0x28
            ? "ARM"
            : `machine=${machine.toString(16)}`;
  const typeLabel =
    type === 2
      ? "executable"
      : type === 3
        ? "shared object"
        : type === 1
          ? "relocatable"
          : `type=${type.toString(16)}`;
  return `ELF ${bitness} ${endian} ${typeLabel}, ${machineLabel}`;
};

export { probeElf };
