"use strict";

export async function parseBaseRelocations(file, dataDirs, rvaToOff, addCoverageRegion) {
  const dir = dataDirs.find(d => d.name === "BASERELOC");
  if (!dir?.rva || dir.size < 8) return null;
  const start = rvaToOff(dir.rva);
  if (start == null) return null;
  addCoverageRegion("BASERELOC (.reloc)", start, dir.size);
  const end = start + dir.size;
  const blocks = [];
  let off = start;
  while (off + 8 <= end) {
    const dv = new DataView(await file.slice(off, off + 8).arrayBuffer());
    const VirtualAddress = dv.getUint32(0, true);
    const SizeOfBlock = dv.getUint32(4, true);
    if (!VirtualAddress || SizeOfBlock < 8) break;
    const entryCount = Math.floor((SizeOfBlock - 8) / 2);
    blocks.push({ VirtualAddress, SizeOfBlock, entryCount });
    off += SizeOfBlock;
  }
  const totalEntries = blocks.reduce((sum, block) => sum + block.entryCount, 0);
  return { blocks, totalEntries };
}

