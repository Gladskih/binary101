"use strict";

import { peProbe } from "./pe/signature.js";

export type MzProbeKind = "mz" | "pe" | "ne" | "le" | "lx";

export interface MzProbeResult {
  kind: MzProbeKind;
  eLfanew: number;
}

const probeMzFormat = async (file: File, dv: DataView): Promise<MzProbeResult | null> => {
  const mz = peProbe(dv);
  if (!mz) return null;
  const eLfanew = mz.e_lfanew >>> 0;
  if (eLfanew === 0) return { kind: "mz", eLfanew };
  if (eLfanew + 4 > file.size) return { kind: "mz", eLfanew };
  const sigLength = Math.min(4, file.size - eLfanew);
  let sigBytes: Uint8Array;
  if (eLfanew + sigLength <= dv.byteLength) {
    sigBytes = new Uint8Array(dv.buffer, dv.byteOffset + eLfanew, sigLength);
  } else {
    sigBytes = new Uint8Array(await file.slice(eLfanew, eLfanew + sigLength).arrayBuffer());
  }
  const sigText = String.fromCharCode(...sigBytes);
  if (sigText.startsWith("PE\0\0")) return { kind: "pe", eLfanew };
  const shortSig = sigText.slice(0, 2);
  if (shortSig === "NE") return { kind: "ne", eLfanew };
  if (shortSig === "LE") return { kind: "le", eLfanew };
  if (shortSig === "LX") return { kind: "lx", eLfanew };
  return { kind: "mz", eLfanew };
};

export { probeMzFormat };
