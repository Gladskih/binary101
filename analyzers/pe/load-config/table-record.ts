"use strict";

import type { PeLoadConfigTable, PeLoadConfigTableKind } from "./index.js";
import { decodeGfidsFlags, GFIDS_FLAG_MASK } from "./gfids.js";

const decodeGfidsMetadata = (
  metadataBytes: number[]
): Pick<PeLoadConfigTable["entries"][number], "gfidsFlags" | "unknownGfidsFlagBits"> => {
  const flags = metadataBytes[0] ?? 0;
  if (flags === 0) return {};
  const unknownGfidsFlagBits = flags & ~GFIDS_FLAG_MASK;
  return {
    gfidsFlags: decodeGfidsFlags(flags),
    ...(unknownGfidsFlagBits ? { unknownGfidsFlagBits } : {})
  };
};

export const decodeLoadConfigTableEntry = (
  view: DataView,
  index: number,
  kind: PeLoadConfigTableKind
): PeLoadConfigTable["entries"][number] | null => {
  const rva = view.getUint32(0, true);
  if (rva === 0) return null;
  const metadataBytes = Array.from(
    { length: Math.max(0, view.byteLength - Uint32Array.BYTES_PER_ELEMENT) },
    (_, byteIndex) => view.getUint8(Uint32Array.BYTES_PER_ELEMENT + byteIndex)
  );
  return {
    index,
    rva,
    ...(metadataBytes.length ? { metadataBytes } : {}),
    ...(kind === "guardFid" ? decodeGfidsMetadata(metadataBytes) : {})
  };
};
