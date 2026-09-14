import type { ElfInstructionSetUsage } from "../analyzers/elf/disassembly-types.js";
import { escapeHtml } from "../html-utils.js";

const escapeAarch64Text = (value: string): string => escapeHtml(value.replaceAll("&", "&amp;"));

// All names and descriptions come from the package's pinned LLVM feature metadata.
// https://github.com/Gladskih/llvm-aarch64-disasm/blob/main/docs/metadata.md

// Exact predicates reviewed against LLVM 21.1.8; never infer semantics from name substrings.
// https://github.com/llvm/llvm-project/blob/llvmorg-21.1.8/llvm/lib/Target/AArch64/AArch64InstrInfo.td#L303
const STREAMING_NOTES: Readonly<Record<string, string>> = {
  HasNEON: "Not guaranteed",
  HasNEONandIsStreamingSafe: "Allowed in either mode",
  HasNEONandIsSME2p2StreamingSafe: "Requires SME2.2 in streaming mode"
};

const streamingNote = (set: ElfInstructionSetUsage): string => {
  if (set.aarch64Predicates?.length !== 1) return "Not classified";
  return STREAMING_NOTES[set.aarch64Predicates[0]!.name] ?? "Not classified";
};

const renderDetectedRow = (set: ElfInstructionSetUsage): string => {
  return `<tr><td>${escapeAarch64Text(set.label)}</td>` +
    `<td class="isaTable__count">${set.instructionCount}</td>` +
    `<td>${escapeAarch64Text(streamingNote(set))}</td>` +
    `<td>${escapeAarch64Text(set.description)}</td></tr>`;
};

export const renderAarch64RequirementTable = (sets: ElfInstructionSetUsage[] = []): string => {
  if (!sets.length) return "";
  return `<div class="tableWrap"><table class="table aarch64IsaTable"><thead><tr>` +
    `<th>Requirement</th><th class="isaTable__count">Instr.</th>` +
    `<th>Streaming SVE mode</th><th>What it is</th></tr></thead><tbody>` +
    sets.map(renderDetectedRow).join("") +
    `</tbody></table></div><div class="smallNote dim">` +
    `All detected requirement combinations are included. Descriptions explain the ` +
    `referenced extensions, not additional requirements. Streaming notes are based on reviewed ` +
    `LLVM predicates, not an execution-mode analysis; unclassified gates do not imply compatibility.</div>`;
};
