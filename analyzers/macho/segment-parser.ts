"use strict";

import { bigFromUint32, readFixedString, subView } from "./format.js";
import type { MachOSegment, MachOSection } from "./types.js";

const parseSegment = (
  cmdView: DataView,
  loadCommandIndex: number,
  is64: boolean,
  little: boolean,
  nextSectionIndex: { value: number },
  issues: string[]
): MachOSegment | null => {
  // Layout comes from segment_command / segment_command_64 and section / section_64
  // in mach-o/loader.h.
  const segmentHeaderSize = is64 ? 72 : 56;
  const sectionSize = is64 ? 80 : 68;
  if (cmdView.byteLength < segmentHeaderSize) {
    issues.push(`Load command ${loadCommandIndex}: segment command is truncated.`);
    return null;
  }
  const segmentName = readFixedString(cmdView, 8, 16);
  const vmaddr = is64 ? cmdView.getBigUint64(24, little) : bigFromUint32(cmdView.getUint32(24, little));
  const vmsize = is64 ? cmdView.getBigUint64(32, little) : bigFromUint32(cmdView.getUint32(28, little));
  const fileoff = is64 ? cmdView.getBigUint64(40, little) : bigFromUint32(cmdView.getUint32(32, little));
  const filesize = is64 ? cmdView.getBigUint64(48, little) : bigFromUint32(cmdView.getUint32(36, little));
  const maxprot = cmdView.getUint32(is64 ? 56 : 40, little);
  const initprot = cmdView.getUint32(is64 ? 60 : 44, little);
  const nsects = cmdView.getUint32(is64 ? 64 : 48, little);
  const flags = cmdView.getUint32(is64 ? 68 : 52, little);
  const sections: MachOSection[] = [];
  const availableSections = Math.floor(Math.max(0, cmdView.byteLength - segmentHeaderSize) / sectionSize);
  if (availableSections < nsects) {
    issues.push(
      `Load command ${loadCommandIndex}: segment ${segmentName || "<unnamed>"} declares ${nsects} sections but only ${availableSections} fit in the command.`
    );
  }
  for (let sectionNumber = 0; sectionNumber < Math.min(nsects, availableSections); sectionNumber += 1) {
    const sectionOffset = segmentHeaderSize + sectionNumber * sectionSize;
    const sectionView = subView(cmdView, sectionOffset, sectionSize);
    const align = sectionView.getUint32(is64 ? 52 : 44, little);
    const flagsValue = sectionView.getUint32(is64 ? 64 : 56, little);
    sections.push({
      index: nextSectionIndex.value,
      segmentName: readFixedString(sectionView, 16, 16),
      sectionName: readFixedString(sectionView, 0, 16),
      addr: is64 ? sectionView.getBigUint64(32, little) : bigFromUint32(sectionView.getUint32(32, little)),
      size: is64 ? sectionView.getBigUint64(40, little) : bigFromUint32(sectionView.getUint32(36, little)),
      offset: sectionView.getUint32(is64 ? 48 : 40, little),
      align,
      reloff: sectionView.getUint32(is64 ? 56 : 48, little),
      nreloc: sectionView.getUint32(is64 ? 60 : 52, little),
      flags: flagsValue,
      reserved1: sectionView.getUint32(is64 ? 68 : 60, little),
      reserved2: sectionView.getUint32(is64 ? 72 : 64, little),
      reserved3: is64 ? sectionView.getUint32(76, little) : null
    });
    nextSectionIndex.value += 1;
  }
  return {
    loadCommandIndex,
    name: segmentName,
    vmaddr,
    vmsize,
    fileoff,
    filesize,
    maxprot,
    initprot,
    nsects,
    flags,
    sections
  };
};

export { parseSegment };
