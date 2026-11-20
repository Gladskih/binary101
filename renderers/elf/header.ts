import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import { ELF_CLASS, ELF_DATA, ELF_TYPE } from "../../analyzers/elf/constants.js";
import type { ElfReport } from "../../analyzers/elf/types.js";
import { renderElfSectionStart, renderElfSectionEnd } from "./collapsible-section.js";
import { renderElfHeaderFlags } from "./header-flags.js";
import { renderHeaderOptions, renderMachine, renderOsAbi } from "./header-options.js";
import { formatElfHex } from "./value-format.js";

const unavailableHeaderValue = '<span class="dim">Unavailable</span>';
const headerValue = <Value>(
  value: Value | undefined, format: (value: Value) => string
): string => value === undefined ? unavailableHeaderValue : format(value);

const headerTableValue = (count: number | undefined, offset: bigint | undefined): string =>
  count === undefined && offset === undefined ? unavailableHeaderValue :
    `${headerValue(count, value => `${value} entries`)} @ ${headerValue(offset, formatElfHex)}`;

const headerSize = (size: number | undefined): string =>
  headerValue(size, value => `${value} bytes`);

export function renderHeader(elf: ElfReport, out: string[]): void {
  // Field meanings: System V gABI, sections 2.1 and 2.2.
  // https://gabi.xinuos.com/elf/02-eheader.html
  const h = elf.header;
  out.push(renderElfSectionStart(`ELF header`));
  out.push(`<dl>`);
  out.push(renderDefinitionRow("Class", renderHeaderOptions(elf.ident.classByte, ELF_CLASS),
    "Selects the 32-bit or 64-bit layout of ELF structures."));
  out.push(renderDefinitionRow("Data", renderHeaderOptions(elf.ident.dataByte, ELF_DATA),
    "Specifies byte order for decoding multibyte numbers: little-endian or big-endian."));
  out.push(renderDefinitionRow("OS ABI", renderOsAbi(elf.ident.osabi),
    "Identifies operating system and binary interface conventions used by this file."));
  out.push(renderDefinitionRow("ABI version", escapeHtml(elf.ident.abiVersion),
    "Distinguishes binary interface revisions; its meaning depends on the selected OS ABI."));
  out.push(renderDefinitionRow("Type", headerValue(h.type, value => renderHeaderOptions(value, ELF_TYPE)),
    "Identifies the file's role: relocatable object, executable, shared object or core dump."));
  out.push(renderDefinitionRow("Machine", headerValue(h.machine, renderMachine),
    "Identifies the target processor architecture used to interpret machine code."));
  const flags = h.flags !== undefined && h.machine !== undefined
    ? renderElfHeaderFlags({ flags: h.flags, machine: h.machine }, elf.ident) : unavailableHeaderValue;
  out.push(renderDefinitionRow("Flags (e_flags)", flags,
    "Processor-specific flags. Highlighted chips show set bits or the selected ABI/ISA value; " +
    "dim chips show other defined choices for this architecture and ABI."));
  out.push(renderDefinitionRow("Entry", headerValue(h.entry, formatElfHex),
    "Virtual address where execution starts. Zero means no entry point."));
  out.push(renderDefinitionRow("Program headers", headerTableValue(h.phnum, h.phoff),
    "Segment descriptions for loading. Shows the number of entries @ byte offset in the file."));
  out.push(renderDefinitionRow("Section headers", headerTableValue(h.shnum, h.shoff),
    "Section descriptions for linking and analysis. " +
    "Shows the number of entries @ byte offset in the file."));
  out.push(renderDefinitionRow("Header size", headerSize(h.ehsize),
    "Size of the ELF header itself."));
  out.push(renderDefinitionRow("PH entry size", headerSize(h.phentsize),
    "Size of one program header record, used to locate successive records."));
  out.push(renderDefinitionRow("SH entry size", headerSize(h.shentsize),
    "Size of one section header record, used to locate successive records."));
  out.push(`</dl>`);
  out.push(renderElfSectionEnd());
}
