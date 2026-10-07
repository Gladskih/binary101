import { concatenateBytes, encodeUint16, encodeUint32, encodeUint64 } from "./dwarf-fixture-encoding.js";

// DWARF 5 7.3.5.3: signature slots, row slots, column ids, offsets, then sizes.
export const encodeDwarfPackageIndex = (signature = 2n, version: 2 | 5 = 5): number[] => concatenateBytes(
  version === 5 ? [...encodeUint16(5), 0, 0] : encodeUint32(2),
  [2, 1, 2].flatMap(encodeUint32),
  encodeUint64(signature), encodeUint64(0),
  [1, 0, 1, 3, 0, 0, 8, 8].flatMap(encodeUint32)
);
