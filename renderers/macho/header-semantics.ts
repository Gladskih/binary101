"use strict";

import { machOMagicName } from "../../analyzers/macho/format.js";
import { cpuSubtypeName, cpuTypeName, fileTypeName, headerFlags } from "../../analyzers/macho/identity-info.js";
import type { MachOFatSlice, MachOFileHeader } from "../../analyzers/macho/types.js";

const cpuLabel = (cputype: number, cpusubtype: number): string => {
  const subtype = cpuSubtypeName(cputype, cpusubtype);
  const type = cpuTypeName(cputype);
  return subtype ? `${type} (${subtype})` : type;
};

const magicLabel = (magic: number): string => machOMagicName(magic) || `0x${magic.toString(16)}`;
const fileTypeLabel = (filetype: number): string => fileTypeName(filetype) || `0x${filetype.toString(16)}`;
const headerFlagLabels = (flags: number): string[] => headerFlags(flags);
const headerCpuLabel = (header: MachOFileHeader): string => cpuLabel(header.cputype, header.cpusubtype);
const fatSliceCpuLabel = (slice: MachOFatSlice): string => cpuLabel(slice.cputype, slice.cpusubtype);

export { fatSliceCpuLabel, fileTypeLabel, headerCpuLabel, headerFlagLabels, magicLabel };
