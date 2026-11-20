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
  // gABI 2.2 e_ident is 16 bytes and identifies ELF even if fixed fields are truncated.
  if (dv.byteLength < 16) return null;
  if (dv.getUint32(0, false) !== 0x7f454c46) return null;
  const classByte = dv.getUint8(4);
  const dataByte = dv.getUint8(5);
  const bitness = classByte === 1 ? "32-bit" : classByte === 2 ? "64-bit" : "?";
  const endian = dataByte === 1 ? "LSB" : dataByte === 2 ? "MSB" : "?";
  const description = `ELF ${bitness} ${endian}`;
  if (dv.byteLength < 0x14 || endian === "?" || bitness === "?") return description;
  const type = dv.getUint16(0x10, dataByte === 1);
  const machine = dv.getUint16(0x12, dataByte === 1);
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
  return `${description}${elfTypeSuffix(type)}, ${machineLabel}`;
};

export { probeElf };
