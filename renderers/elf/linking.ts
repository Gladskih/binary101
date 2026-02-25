"use strict";

import { dd, safe } from "../../html-utils.js";
import { DYNAMIC_FLAGS, DYNAMIC_FLAGS_1 } from "../../analyzers/elf/constants.js";
import type {
  ElfDynamicInfo,
  ElfInterpreterInfo,
  ElfOptionEntry,
  ElfParseResult
} from "../../analyzers/elf/types.js";
import { formatElfHex, formatElfList, formatElfMaybeHumanSize } from "./value-format.js";

const formatAddrOrDash = (value: bigint | null | undefined): string => (value != null ? safe(formatElfHex(value)) : "-");

const formatRangeOrDash = (range: { vaddr: bigint; size: bigint } | null | undefined): string => {
  if (!range) return "-";
  return `${safe(formatElfHex(range.vaddr))} (${formatElfMaybeHumanSize(range.size)})`;
};

const collectIssues = (interpreter?: ElfInterpreterInfo, dynamic?: ElfDynamicInfo): string[] => {
  const issues: string[] = [];
  interpreter?.issues?.forEach(issue => issues.push(`PT_INTERP: ${issue}`));
  dynamic?.issues?.forEach(issue => issues.push(`Dynamic: ${issue}`));
  return issues;
};

const toUint32 = (value: number): number => value >>> 0;

const describeDynamicFlags = (value: number, knownFlags: ElfOptionEntry[]): string => {
  const normalized = toUint32(value);
  const enabledFlags = knownFlags.filter(([bit]) => (normalized & toUint32(bit)) !== 0);
  const knownMask = knownFlags.reduce((mask, [bit]) => (mask | toUint32(bit)) >>> 0, 0);
  const unknownMask = (normalized & (~knownMask >>> 0)) >>> 0;
  const items = enabledFlags.length
    ? enabledFlags
        .map(([, name, explanation]) => {
          const details = explanation ? `: ${safe(explanation)}` : "";
          return `<li><span class="mono">${safe(name)}</span>${details}</li>`;
        })
        .join("")
    : `<li>No known flags set.</li>`;
  const unknownItem =
    unknownMask !== 0
      ? `<li><span class="mono">Unknown bits: ${safe(formatElfHex(unknownMask, 8))}</span></li>`
      : "";
  return (
    `<div><span class="mono">${safe(formatElfHex(normalized, 8))}</span></div>` +
    `<ul style="margin:.35rem 0 0 1.1rem">${items}${unknownItem}</ul>`
  );
};

const formatDynamicFlags = (value: number | null | undefined, knownFlags: ElfOptionEntry[]): string =>
  value != null ? describeDynamicFlags(value, knownFlags) : "-";

export function renderElfLinking(elf: ElfParseResult, out: string[]): void {
  const interpreter = elf.interpreter;
  const dynamic = elf.dynamic;
  if (!interpreter && !dynamic) return;

  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Dynamic linking</h4>`);
  out.push(
    `<div class="smallNote">Interpreter and DT_* tags describe how the dynamic loader resolves shared libraries and startup routines.</div>`
  );
  out.push(`<dl>`);

  if (interpreter) {
    const path = interpreter.path ? `<span class="mono">${safe(interpreter.path)}</span>` : "-";
    out.push(dd("Interpreter (PT_INTERP)", path));
  }

  if (dynamic) {
    out.push(dd("Needed (DT_NEEDED)", formatElfList(dynamic.needed)));
    out.push(dd("SONAME (DT_SONAME)", dynamic.soname ? safe(dynamic.soname) : "-"));
    out.push(dd("RPATH (DT_RPATH)", dynamic.rpath ? safe(dynamic.rpath) : "-"));
    out.push(dd("RUNPATH (DT_RUNPATH)", dynamic.runpath ? safe(dynamic.runpath) : "-"));
    out.push(dd("Init (DT_INIT)", formatAddrOrDash(dynamic.init)));
    out.push(dd("Fini (DT_FINI)", formatAddrOrDash(dynamic.fini)));
    out.push(dd("Preinit array", formatRangeOrDash(dynamic.preinitArray)));
    out.push(dd("Init array", formatRangeOrDash(dynamic.initArray)));
    out.push(dd("Fini array", formatRangeOrDash(dynamic.finiArray)));
    out.push(
      dd(
        "Flags (DT_FLAGS)",
        formatDynamicFlags(dynamic.flags, DYNAMIC_FLAGS),
        "Base dynamic-loader behavior flags. Known bits are decoded below."
      )
    );
    out.push(
      dd(
        "Flags_1 (DT_FLAGS_1)",
        formatDynamicFlags(dynamic.flags1, DYNAMIC_FLAGS_1),
        "Extended dynamic-loader behavior flags. Known bits are decoded below."
      )
    );
  }

  out.push(`</dl>`);

  const issues = collectIssues(interpreter, dynamic);
  if (issues.length) {
    const items = issues.map(issue => `<li>${safe(issue)}</li>`).join("");
    out.push(
      `<details style="margin-top:.35rem"><summary class="dim" style="cursor:pointer">Notes</summary><ul>${items}</ul></details>`
    );
  }

  out.push(`</section>`);
}
