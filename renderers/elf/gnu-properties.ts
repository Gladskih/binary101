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
  if (machine === 3 || machine === 62) return describeX86Property(type, value);
  return `0x${value.toString(16)}`;
};

const describeX86Property = (type: number, value: bigint): string => {
  if (type === 0xc0000002) {
    return `Compatible with: ${featureDescription(value, ["IBT", "SHSTK"])}`;
  }
  if (type === 0xc0008002 || type === 0xc0010002) {
    return `ISA ${type === 0xc0008002 ? "required" : "used"}: ` +
      featureDescription(value, ["x86-64-baseline", "x86-64-v2", "x86-64-v3", "x86-64-v4"]);
  }
  return `0x${value.toString(16)}`;
};

const propertyName = (machine: number, type: number): string => {
  const generic = ({ 1: "GNU_PROPERTY_STACK_SIZE", 2: "GNU_PROPERTY_NO_COPY_ON_PROTECTED",
    0xb0008000: "GNU_PROPERTY_1_NEEDED" } as Record<number, string>)[type];
  if (generic) return generic;
  if (machine === 183 && type === 0xc0000000) return "GNU_PROPERTY_AARCH64_FEATURE_1_AND";
  if (machine === 3 || machine === 62) return ({
    0xc0000002: "GNU_PROPERTY_X86_FEATURE_1_AND", 0xc0008002: "GNU_PROPERTY_X86_ISA_1_NEEDED",
    0xc0010002: "GNU_PROPERTY_X86_ISA_1_USED"
  } as Record<number, string>)[type] ?? "";
  return "";
};

export const renderElfGnuProperties = (elf: ElfParseResult, out: string[]): void => {
  const rows = elf.notes?.entries.flatMap(note => (note.properties ?? []).map(property => {
    const name = propertyName(elf.header.machine, property.type);
    return `<tr><td>${escapeHtml([note.source, ...note.sourceAliases ?? []].join(", "))}</td>` +
      `<td>${name ? `${name} · ` : ""}0x${property.type.toString(16)}</td>` +
      `<td>${escapeHtml(typeof property.value === "bigint"
        ? property.type === 2 ? "No payload" : `0x${property.value.toString(16)}` : property.value)}</td>` +
      `<td>${escapeHtml(describeElfGnuProperty(property, elf.header.machine))}</td></tr>`;
  })) ?? [];
  if (!rows.length) return;
  out.push('<h4>GNU properties</h4><p class="smallNote">These bits describe the binary. Runtime ' +
    'activation depends on the CPU, operating system and loader. IBT and BTI check indirect branch ' +
    'targets, SHSTK and GCS protect return addresses in a separate stack, and PAC authenticates pointers.</p>' +
    `<div class="tableWrap"><table class="table">` +
    `<thead><tr><th>Source</th><th>Property type</th><th>Raw value</th><th>Meaning</th></tr></thead>` +
    `<tbody>${rows.join("")}</tbody></table></div>`);
};
