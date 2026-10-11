import { isaDataBytes } from "./isa-known-data.js";

export const createElfIsaDataFile = (): Uint8Array<ArrayBuffer> => {
  const bytes = new Uint8Array(768);
  const view = new DataView(bytes.buffer);
  // Sectionless ELF64: PT_LOAD maps the file; PT_DYNAMIC supplies .dynsym and a hash count.
  // https://gabi.xinuos.com/elf/02-eheader.html ; 07-pheader.html ; 08-dynamic.html
  bytes.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]);
  view.setUint16(16, 3, true);
  view.setUint16(18, 62, true);
  view.setUint32(20, 1, true);
  view.setBigUint64(24, 0x1140n, true);
  view.setBigUint64(32, 64n, true);
  view.setUint16(52, 64, true);
  view.setUint16(54, 56, true);
  view.setUint16(56, 2, true);
  for (const [index, type, offset, size, flags] of [[0, 1, 0, 768, 5], [1, 2, 384, 112, 4]]) {
    const base = 64 + index! * 56;
    view.setUint32(base, type!, true);
    view.setUint32(base + 4, flags!, true);
    view.setBigUint64(base + 8, BigInt(offset!), true);
    view.setBigUint64(base + 16, 0x1000n + BigInt(offset!), true);
    view.setBigUint64(base + 32, BigInt(size!), true);
    view.setBigUint64(base + 40, BigInt(size!), true);
    view.setBigUint64(base + 48, 8n, true);
  }
  const names = new TextEncoder().encode("\0_Z5value\0");
  bytes.set(names, 256);
  view.setUint32(216, 1, true);
  view.setUint8(220, 0x10); // GLOBAL NOTYPE; data is proved by the successful Itanium AST.
  view.setUint16(222, 1, true);
  view.setBigUint64(224, 0x1148n, true);
  view.setBigUint64(232, 8n, true);
  view.setUint32(288, 1, true);
  view.setUint32(292, 2, true);
  view.setUint32(296, 1, true);
  bytes.set(isaDataBytes(62).subarray(0, 16), 320);
  // DT_INIT is deliberately a conflicting pointer into the data object's interior.
  [[5n, 0x1100n], [10n, BigInt(names.length)], [6n, 0x10c0n], [11n, 24n],
    [4n, 0x1120n], [12n, 0x114cn], [0n, 0n]].forEach(([tag, value], index) => {
    view.setBigUint64(384 + index * 16, tag!, true);
    view.setBigUint64(392 + index * 16, value!, true);
  });
  return bytes;
};
