"use strict";

const detectELF = (dv: DataView): string | null => {
  if (dv.byteLength < 0x14) return null;
  if (dv.getUint32(0, false) !== 0x7f454c46) return null;
  const c = dv.getUint8(4);
  const d = dv.getUint8(5);
  const le = d === 1;
  const t = dv.getUint16(0x10, le);
  const m = dv.getUint16(0x12, le);
  const bit = c === 1 ? "32-bit" : c === 2 ? "64-bit" : "?";
  const endian = d === 1 ? "LSB" : d === 2 ? "MSB" : "?";
  const mach =
    m === 0x3e
      ? "x86-64"
      : m === 0x03
        ? "x86"
        : m === 0xb7
          ? "ARM64"
          : m === 0x28
            ? "ARM"
            : `machine=${m.toString(16)}`;
  const kind =
    t === 2
      ? "executable"
      : t === 3
        ? "shared object"
        : t === 1
          ? "relocatable"
          : `type=${t.toString(16)}`;
  return `ELF ${bit} ${endian} ${kind}, ${mach}`;
};

const detectMachO = (dv: DataView): string | null => {
  if (dv.byteLength < 4) return null;
  const be = dv.getUint32(0, false);
  const le = dv.getUint32(0, true);
  if (be === 0xfeedface || le === 0xcefaedfe) return "Mach-O 32-bit";
  if (be === 0xfeedfacf || le === 0xcffaedfe) return "Mach-O 64-bit";
  if (be === 0xcafebabe || le === 0xbebafeca) return "Mach-O universal (Fat)";
  return null;
};

export { detectELF, detectMachO };
