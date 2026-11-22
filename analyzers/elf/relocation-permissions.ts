import { ELF_FILE_TYPE, ELF_SEGMENT_TYPE } from "./abi-constants.js";
import { findElfDynamicSegment, type ElfDynamicTable } from "./dynamic-entries.js";
import type { ElfRelocationImage, ElfRelocationTable } from "./relocation-types.js";
import type { ElfBinaryLayout } from "./binary-layout-types.js";
import { createElfRangeCoverage } from "./range-coverage.js";

// gABI 7.4 and 8.3: PF_W is the load segment's write flag; DT_TEXTREL
// (presence) or DF_TEXTREL permits writes to segments without PF_W.
// https://gabi.xinuos.com/elf/08-dynamic.html#dynamic-section
export const createElfRelocationPermissionCheck = (
  image: ElfRelocationImage, dynamic: ElfDynamicTable, layout: ElfBinaryLayout, issues: string[]
) => {
  if (image.header.type !== ELF_FILE_TYPE.EXEC && image.header.type !== ELF_FILE_TYPE.DYN) return undefined;
  if (!dynamic.terminated || !findElfDynamicSegment(image.programHeaders) || dynamic.entries.some(({ tag, value }) =>
    tag === 22 || (tag === 30 && (value & 4n) !== 0n))) return undefined;
  const writable = image.programHeaders.filter(segment => segment.type === ELF_SEGMENT_TYPE.LOAD &&
    (segment.flags & 2) !== 0)
    .map(segment => ({ start: segment.vaddr, end: segment.vaddr + segment.memsz }));
  const writableCovers = createElfRangeCoverage(writable);
  let reported = false;
  return (table: ElfRelocationTable, offset: bigint, writeSize: bigint | undefined): void => {
    if (reported || !table.sources.some(source => source.startsWith("DT_"))) return;
    const width = table.encoding === "RELR" || table.encoding === "AUTH_RELR" ? BigInt(layout.wordSize) : writeSize;
    if (!width) return;
    const end = offset + width;
    // The relocation resolver has already checked that the whole write is mapped.
    if (writableCovers(offset, end)) return;
    issues.push(`Dynamic relocation at 0x${offset.toString(16)} writes to a non-writable PT_LOAD ` +
      "without DT_TEXTREL or DF_TEXTREL.");
    reported = true;
  };
};
