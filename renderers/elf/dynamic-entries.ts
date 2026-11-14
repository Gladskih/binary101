import { ELF_DYNAMIC_TAG_DESCRIPTIONS } from "../../analyzers/elf/dynamic-tags.js";
import { ELF_DYNAMIC_TAG } from "../../analyzers/elf/abi-constants.js";
import { DYNAMIC_FLAGS, DYNAMIC_FLAGS_1 } from "../../analyzers/elf/constants.js";
import type { ElfDynamicInfo, ElfOptionEntry } from "../../analyzers/elf/types.js";
import {
  escapeHtmlText, renderDefinitionRow, renderFlagChips, renderOptionChips
} from "../../html-utils.js";

type DynamicRecord = ElfDynamicInfo["entries"][number];

// llvm-readobj accepts DT_REL, DT_RELA and DT_CREL as DT_PLTREL values.
// https://github.com/llvm/llvm-project/blob/main/llvm/tools/llvm-readobj/ELFDumper.cpp
const pltRelocationFormats: ElfOptionEntry[] = [
  [ELF_DYNAMIC_TAG.RELA, "DT_RELA", "PLT relocations have explicit addends."],
  [ELF_DYNAMIC_TAG.REL, "DT_REL", "PLT relocations have implicit addends."],
  [ELF_DYNAMIC_TAG.CREL, "DT_CREL", "PLT relocations use the experimental LLVM CREL encoding."]
];

// GNU/Sun flag assignments: https://github.com/bminor/glibc/blob/master/elf/elf.h
// Sun feature meanings: https://docs.oracle.com/cd/E19683-01/817-3677/chapter6-42444/
const flagFamilies: Record<number, ElfOptionEntry[]> = {
  30: DYNAMIC_FLAGS,
  0x6ffffffb: DYNAMIC_FLAGS_1,
  0x6ffffdfc: [
    [1, "DTF_1_PARINIT", "Partial initialization is required."],
    [2, "DTF_1_CONFEXP", "Alternative object expecting a runtime linker configuration file."]
  ],
  0x6ffffdfd: [
    [1, "DF_P1_LAZYLOAD", "Load the following dependency lazily."],
    [2, "DF_P1_GROUPPERM", "Restrict availability of the following dependency's symbols."]
  ]
};

const rawHex = (value: number | bigint): string =>
  value < 0 ? `-0x${(-BigInt(value)).toString(16)}` : `0x${value.toString(16)}`;

const formatFlags = (tag: number, value: bigint): string => {
  // The shared chips use uint32 masks. Preserve ELF64 bits above that range separately.
  const highBits = value & ~0xffffffffn;
  return renderFlagChips(Number(value & 0xffffffffn), flagFamilies[tag]!, highBits
    ? `<span class="opt sel" title="Unknown flag bits">UNKNOWN_BITS_${rawHex(highBits)}</span>`
    : "");
};

const describeString = (value: string | null | undefined): string =>
  value == null ? "Unresolved string" : value === "" ? "Empty string" : escapeHtmlText(value);

const valueDetail = (entry: DynamicRecord, kind: string): string => {
  switch (kind) {
    case "string": return ` <span>→ ${describeString(entry.string)}</span>`;
    case "bytes": return ` <span class="dim">(${entry.value} bytes)</span>`;
    case "count": return ` <span class="dim">(${entry.value} records)</span>`;
    case "presence": return ` <span class="dim">(value ignored)</span>`;
    default: return "";
  }
};

const renderValue = (entry: DynamicRecord, kind: string): string => {
  const raw = `<code>${rawHex(entry.value)}</code>`;
  if (kind === "flags") return raw + formatFlags(Number(entry.tag), entry.value);
  if (kind === "relocation") {
    return raw + renderOptionChips(Number(entry.value), pltRelocationFormats) +
      (pltRelocationFormats.some(([tag]) => BigInt(tag) === entry.value) ? "" :
      `<span class="dim">Unknown relocation encoding</span>`);
  }
  return raw + valueDetail(entry, kind);
};

const renderRecord = (entry: DynamicRecord, index: number): string => {
  const definition = typeof entry.tag === "number" && ELF_DYNAMIC_TAG_DESCRIPTIONS[entry.tag];
  const [name, kind, description] = definition || [`Unknown tag ${rawHex(entry.tag)}`, "value",
    "Unknown tag; OS/processor-specific or reserved semantics are not inferred."];
  return renderDefinitionRow(name, renderValue(entry, kind),
    `Entry ${index}; d_tag = ${rawHex(entry.tag)}. ${description}` +
    (kind === "presence" ? " Presence enables this behavior; d_un is ignored." : ""));
};

export const renderElfDynamicEntries = (entries: ElfDynamicInfo["entries"]): string =>
  entries.length ? `<h4>Dynamic entries (${entries.length})</h4>` +
    `<dl class="elfDynamicEntries" data-elf-dynamic-entries>` +
    `${entries.map(renderRecord).join("")}</dl>` : "";

const renderMissingTag = (tag: number, state: string): string => {
  const [name, kind, description] = ELF_DYNAMIC_TAG_DESCRIPTIONS[tag]!;
  return renderDefinitionRow(name, `<span class="dim">${state}</span>` +
    (kind === "flags" ? formatFlags(tag, 0n) : ""), description +
    (kind === "flags" ? " Dim chips show defined choices; no mask value is available." : ""));
};

export const renderElfDynamicTagCoverage = (
  dynamic: Pick<ElfDynamicInfo, "entries" | "terminated">
): string => {
  const present = new Set(dynamic.entries.map(entry => entry.tag));
  const missing = Object.keys(ELF_DYNAMIC_TAG_DESCRIPTIONS).map(Number)
    .filter(tag => !present.has(tag));
  const state = dynamic.terminated ? "Absent" : "Not determined (DT_NULL not verified)";
  return `<div data-elf-dynamic-coverage><h4>Tag coverage</h4><p class="smallNote">` +
    (dynamic.terminated ? "Dynamic table checked through DT_NULL. " +
      `${missing.length} known tag types are absent.` :
      "DT_NULL was not verified. Tags not encountered in decoded entries may occur " +
      "in unread data; their absence cannot be confirmed.") + `</p>` +
    `<dl class="elfDynamicEntries">${missing.map(tag => renderMissingTag(tag, state))
      .join("")}</dl></div>`;
};
