// @ts-nocheck
"use strict";

export async function parseExceptionDirectory(file, dataDirs, rvaToOff, addCoverageRegion) {
  const dir = dataDirs.find(d => d.name === "EXCEPTION");
  if (!dir?.rva || dir.size < 12) return null;
  const start = rvaToOff(dir.rva);
  if (start == null) return null;
  addCoverageRegion("EXCEPTION (.pdata)", start, dir.size);
  const count = Math.floor(dir.size / 12);
  const maxSample = Math.min(count, 64);
  const view = new DataView(await file.slice(start, start + Math.min(dir.size, 12 * maxSample)).arrayBuffer());
  const sample = [];
  for (let index = 0; index < maxSample; index++) {
    const base = index * 12;
    const BeginAddress = view.getUint32(base + 0, true);
    const EndAddress = view.getUint32(base + 4, true);
    const UnwindInfoAddress = view.getUint32(base + 8, true);
    sample.push({ BeginAddress, EndAddress, UnwindInfoAddress });
  }
  return { count, sample };
}
