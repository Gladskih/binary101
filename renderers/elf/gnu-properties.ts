import { escapeHtml } from "../../html-utils.js";
import type { ElfGnuProperty } from "../../analyzers/elf/gnu-properties.js";
import type { ElfParseResult } from "../../analyzers/elf/types.js";

// Property bits and architecture assignments: glibc elf/elf.h.
// https://raw.githubusercontent.com/bminor/glibc/master/elf/elf.h
const featureDescription = (value: bigint, names: string[]): string => {
  const features = names.filter((_, index) => (value & (1n << BigInt(index))) !== 0n);
  const unknown = value & ~((1n << BigInt(names.length)) - 1n);
  if (unknown) features.push(`unknown bits 0x${unknown.toString(16)}`);
  return features.join(", ") || "none";
};

export const describeElfGnuProperty = (property: ElfGnuProperty, machine: number): string => {
  const { type, value } = property;
  if (typeof value === "string") return `Raw data: ${value}`;
  if (type === 1) return `Stack size: ${value} bytes`;
  if (type === 2) return "No copy relocations on protected data";
  if (type === 0xb0008000) {
    return `Required: ${featureDescription(value, ["indirect external access"])}`;
  }
  if (machine === 183 && type === 0xc0000000) {
    return `AArch64 features: ${featureDescription(value, ["BTI", "PAC", "GCS"])}`;
  }
  if (machine === 3 || machine === 62) {
    if (type === 0xc0000002) {
      return `Compatible with: ${featureDescription(value, ["IBT", "SHSTK"])}`;
    }
    if (type === 0xc0008002 || type === 0xc0010002) {
      return `ISA ${type === 0xc0008002 ? "required" : "used"}: ` +
        featureDescription(value, ["x86-64-baseline", "x86-64-v2", "x86-64-v3", "x86-64-v4"]);
    }
  }
  return `0x${value.toString(16)}`;
};

export const renderElfGnuProperties = (elf: ElfParseResult, out: string[]): void => {
  const rows = elf.notes?.entries.flatMap(note => (note.properties ?? []).map(property =>
    `<tr><td>${escapeHtml(note.source)}</td><td>0x${property.type.toString(16)}</td>` +
    `<td>${escapeHtml(describeElfGnuProperty(property, elf.header.machine))}</td></tr>`)) ?? [];
  if (!rows.length) return;
  out.push(`<h4>GNU properties</h4><div class="tableWrap"><table class="table">` +
    `<thead><tr><th>Source</th><th>Property type</th><th>Meaning</th></tr></thead>` +
    `<tbody>${rows.join("")}</tbody></table></div>`);
};
