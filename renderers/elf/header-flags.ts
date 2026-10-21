import type { ElfHeader, ElfIdent } from "../../analyzers/elf/types.js";
import { toHex32 } from "../../binary-utils.js";
import { escapeHtml } from "../../html-utils.js";
import definitions from "./header-flags.json" with { type: "json" };

interface FlagField {
  name: string;
  mask: number;
  kind: string;
  values: Array<{ value: number; name: string; description: string }>;
}

// Numeric assignments are pinned in the data's source URLs. ABI-dependent meanings follow:
// https://github.com/RTEMS/sourceware-mirror-binutils-gdb/blob/1f57adffdc6d586e8beb25b55ec13dc1407fdfb3/binutils/readelf.c
// https://github.com/llvm/llvm-project/blob/llvmorg-23.1.3/llvm/lib/Object/ELFObjectFile.cpp
const gpuLayout = (ident: ElfIdent): number => {
  // HSA ABI byte 0..4 denotes code object V2..V6. Other versions remain uninterpreted.
  if (ident.osabi === 64) return ident.abiVersion <= 4 ? ident.abiVersion + 2 : -1;
  // GNU readelf uses V3 flag semantics for unversioned NONE, PAL and Mesa3D objects.
  return [0, 65, 66].includes(ident.osabi) ? 3 : -1;
};

const fieldsForHeader = (header: ElfHeader, ident: ElfIdent): FlagField[] => {
  const context: Record<string, number> = {
    flags: header.flags, osabi: ident.osabi, abiVersion: ident.abiVersion,
    gpuLayout: gpuLayout(ident)
  };
  return Object.values(definitions.catalogs)
    .filter(catalog => catalog.machines.includes(header.machine) &&
      catalog.conditions.every(condition => condition.values.includes(
        (context[condition.field]! & condition.mask) >>> 0)))
    .flatMap(catalog => catalog.fields);
};

const renderChip = (name: string, description: string, value: number, selected: number): string =>
  `<span class="opt ${value === selected ? "sel" : "dim"}" data-accessible-tooltip ` +
  `title="${escapeHtml(description)}">${escapeHtml(name)}</span>`;

const renderField = (field: FlagField, flags: number): string => {
  const value = (flags & field.mask) >>> 0;
  const maskHelp = `${field.name}; mask ${toHex32(field.mask, 8)}.`;
  if (field.kind === "number") {
    return renderChip(`${field.name}: ${toHex32(value, 8)}`,
      `${maskHelp} Numeric field; shown in its original bit position.`, value, value);
  }
  const chips = field.values.map(option => renderChip(option.name,
    `${option.description} Value ${toHex32(option.value, 8)}; ${maskHelp}`, option.value, value));
  if (field.kind === "enum" && !field.values.some(option => option.value === value)) {
    chips.push(renderChip(`Unknown ${field.name}: ${toHex32(value, 8)}`,
      `${maskHelp} This encoded value has no known definition.`, value, value));
  }
  return chips.join("");
};

export const renderElfHeaderFlags = (header: ElfHeader, ident: ElfIdent): string => {
  const fields = fieldsForHeader(header, ident);
  const knownMask = fields.reduce((mask, field) => mask | field.mask, 0);
  const unknown = (header.flags & ~knownMask) >>> 0;
  return `<code>${toHex32(header.flags, 8)}</code>` +
    (fields.length ? "" : `<div class="smallNote">` +
      `No processor-specific flag definitions for this architecture/ABI.</div>`) +
    `<div class="optionsRow">${fields.map(field => renderField(field, header.flags)).join("")}` +
    (unknown ? renderChip(`UNKNOWN_BITS_${toHex32(unknown, 8)}`,
      "Set bits with no known meaning for this architecture and ABI.", unknown, unknown) : "") +
    `</div>`;
};
