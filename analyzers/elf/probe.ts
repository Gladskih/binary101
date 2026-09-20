"use strict";

// gABI e_type: ET_DYN (3) alone cannot identify a library versus PIE.
// https://gabi.xinuos.com/elf/02-eheader.html
function elfTypeSuffix(type: number): string {
  switch (type) {
    case 1: return " relocatable";
    case 2: return " executable";
    case 3: return "";
    default: return ` type=${type.toString(16)}`;
  }
}

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
  return `ELF ${bitness} ${endian}${elfTypeSuffix(type)}, ${machineLabel}`;
};

export { probeElf };
