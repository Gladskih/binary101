"use strict";

import type { PeWindowsParseResult } from "../../analyzers/pe/index.js";
import { renderPeSectionEnd, renderPeSectionStart } from "./collapsible-section.js";
import { renderPeDiagnostics } from "./diagnostics.js";

type PeExceptionSection = NonNullable<PeWindowsParseResult["exception"]>;
type PeExceptionFormat = PeExceptionSection["format"];

interface ExceptionRenderProfile {
  chainedLabel: string;
  handlerLabel: string;
  introNote: string;
  renderFormatNote: (ex: PeExceptionSection, out: string[]) => void;
  renderFormatStats: (ex: PeExceptionSection, out: string[]) => void;
  unwindLabel: string;
}

const renderNoFormatDetails = (): void => undefined;

const renderAmd64UnwindStats = (ex: PeExceptionSection, out: string[]): void => {
  ([
    ["UNWIND_INFO v1 blocks", ex.unwindInfoVersion1Count],
    ["UNWIND_INFO v2 blocks", ex.unwindInfoVersion2Count],
    ["UNWIND_INFO v2 epilog records", ex.epilogUnwindInfoCount],
    ["UNWIND_INFO v2 epilog scopes", ex.epilogScopeCount]
  ] as const).forEach(([label, count]) => {
    if (count != null) out.push(`<dt>${label}</dt><dd>${count}</dd>`);
  });
};

const renderAmd64VersionNote = (ex: PeExceptionSection, out: string[]): void => {
  if ((ex.unwindInfoVersion2Count ?? 0) === 0) return;
  out.push(
    `<div class="smallNote">` +
      `UNWIND_INFO v2 epilog records mark explicit epilog scopes emitted by newer ` +
      `MSVC-compatible toolchains; Microsoft Learn still documents v1 as the public baseline.` +
    `</div>`
  );
};

const getExceptionRenderProfile = (format: PeExceptionFormat): ExceptionRenderProfile => {
  if (format === "arm64") {
    return {
      chainedLabel: "Chained entries",
      handlerLabel: "Handlers present (ARM64 X bit)",
      introNote:
        "ARM64 .pdata stores packed unwind data or points to .xdata records used for " +
        "stack unwinding and exception dispatch.",
      renderFormatNote: renderNoFormatDetails,
      renderFormatStats: renderNoFormatDetails,
      unwindLabel: "Unique unwind descriptions (.xdata or packed .pdata)"
    };
  }
  return {
    chainedLabel: "Chained (CHAININFO)",
    handlerLabel: "Handlers present (EHANDLER/UHANDLER)",
    introNote:
      "x64 .pdata maps code ranges to UNWIND_INFO blocks so Windows can unwind stacks " +
      "for exceptions, cleanup, and debugger walks.",
    renderFormatNote: renderAmd64VersionNote,
    renderFormatStats: renderAmd64UnwindStats,
    unwindLabel: "Unique UNWIND_INFO blocks"
  };
};

export function renderException(ex: PeExceptionSection, out: string[]): void {
  const profile = getExceptionRenderProfile(ex.format);
  out.push(
    renderPeSectionStart(
      "Exception directory (.pdata)",
      `${ex.functionCount ?? 0} function${(ex.functionCount ?? 0) === 1 ? "" : "s"}`
    )
  );
  out.push(`<div class="smallNote">${profile.introNote}</div>`);
  out.push(`<dl>`);
  out.push(`<dt>Functions (RUNTIME_FUNCTION entries)</dt><dd>${ex.functionCount ?? 0}</dd>`);
  out.push(`<dt>${profile.unwindLabel}</dt><dd>${ex.uniqueUnwindInfoCount ?? 0}</dd>`);
  profile.renderFormatStats(ex, out);
  out.push(`<dt>${profile.handlerLabel}</dt><dd>${ex.handlerUnwindInfoCount ?? 0}</dd>`);
  out.push(`<dt>${profile.chainedLabel}</dt><dd>${ex.chainedUnwindInfoCount ?? 0}</dd>`);
  out.push(`<dt>Missing/invalid ranges</dt><dd>${ex.invalidEntryCount ?? 0}</dd>`);
  out.push(`</dl>`);
  profile.renderFormatNote(ex, out);
  if (ex.issues?.length) {
    out.push(renderPeDiagnostics("Exception directory warnings", ex.issues));
  }
  out.push(renderPeSectionEnd());
}
