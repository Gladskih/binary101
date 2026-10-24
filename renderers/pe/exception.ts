"use strict";

import type { PeWindowsParseResult } from "../../analyzers/pe/index.js";
import { renderPeSectionEnd, renderPeSectionStart } from "./collapsible-section.js";
import { renderPeDiagnostics } from "./diagnostics.js";
import { renderExceptionRangeHistogram } from "./exception-range-histogram.js";
import { renderExceptionV3 } from "./exception-v3.js";
import { renderExceptionV12 } from "./exception-v12.js";
import { renderDefinitionRow } from "../../html-utils.js";
import { renderArmntPackedStatistics } from "./exception-armnt.js";
import { renderCeExceptionStatistics } from "./exception-ce.js";
import { renderIa64UnwindStatistics } from "./exception-ia64.js";
import { renderNtRiscStatistics } from "./exception-nt-risc.js";

type PeExceptionSection = NonNullable<PeWindowsParseResult["exception"]>;
type PeExceptionFormat = PeExceptionSection["format"];

interface ExceptionRenderProfile {
  chainedLabel?: string;
  handlerLabel?: string;
  introNote: string;
  renderFormatNote: (ex: PeExceptionSection, out: string[]) => void;
  renderFormatStats: (ex: PeExceptionSection, out: string[]) => void;
  unwindLabel: string;
}

const renderNoFormatDetails = (): void => undefined;

const renderV3Summary = (statistics: NonNullable<PeExceptionSection["unwindInfoV3"]>, out: string[]): void => {
  out.push(renderDefinitionRow("UNWIND_INFO v3 blocks", String(statistics.blockCount)));
  out.push(renderDefinitionRow("UNWIND_INFO v3 epilogs", String(statistics.epilogCount)));
  ([
    ["UNWIND_INFO v3 inherited epilogs", statistics.inheritedEpilogCount],
    ["UNWIND_INFO v3 LARGE prologs", statistics.largePrologCount],
    ["UNWIND_INFO v3 LARGE epilogs", statistics.largeEpilogCount]
  ] as const).forEach(([label, count]) => {
    if (count > 0) out.push(renderDefinitionRow(label, String(count)));
  });
};

const renderAmd64UnwindStats = (ex: PeExceptionSection, out: string[]): void => {
  if (ex.unwindInfoVersion1Count) {
    out.push(renderDefinitionRow("UNWIND_INFO v1 blocks", String(ex.unwindInfoVersion1Count)));
  }
  if (ex.unwindInfoVersion2Count) ([
    ["UNWIND_INFO v2 blocks", ex.unwindInfoVersion2Count],
    ["UNWIND_INFO v2 epilog records", ex.epilogUnwindInfoCount],
    ["UNWIND_INFO v2 epilog scopes", ex.epilogScopeCount]
  ] as const).forEach(([label, count]) => {
    if (count != null) out.push(renderDefinitionRow(label, String(count)));
  });
  if (ex.unwindInfoV3) renderV3Summary(ex.unwindInfoV3, out);
};

const renderAmd64VersionNote = (ex: PeExceptionSection, out: string[]): void => {
  if (ex.unwindInfoV12) out.push(renderExceptionV12(ex.unwindInfoV12));
  if ((ex.unwindInfoVersion2Count ?? 0) > 0) out.push(
    `<div class="smallNote">` +
      `UNWIND_INFO v2 epilog records mark explicit epilog scopes emitted by newer ` +
      `MSVC-compatible toolchains.` +
    `</div>`
  );
  if (ex.unwindInfoV3) out.push(renderExceptionV3(ex.unwindInfoV3));
};

const renderReadyToRunStats = (ex: PeExceptionSection, out: string[]): void => {
  if (ex.exceptionInfoMethodCount != null) {
    out.push(`<dt>ExceptionInfo methods</dt><dd>${ex.exceptionInfoMethodCount}</dd>`);
  }
  ([
    ["Catch clauses", ex.catchClauseCount],
    ["Filter clauses", ex.filterClauseCount],
    ["Finally clauses", ex.finallyClauseCount],
    ["Fault clauses", ex.faultClauseCount]
  ] as const).forEach(([label, count]) => {
    if (count != null) out.push(`<dt>${label}</dt><dd>${count}</dd>`);
  });
};

const renderArmntSummary = (ex: PeExceptionSection, out: string[]): void => {
  if (ex.fragmentEntryCount) out.push(renderDefinitionRow("Function fragments", String(ex.fragmentEntryCount)));
};

const renderArmntDetails = (ex: PeExceptionSection, out: string[]): void => {
  if (ex.armntPacked) out.push(renderArmntPackedStatistics(ex.armntPacked));
};

const getArmProfile = (format: "arm64" | "armnt"): ExceptionRenderProfile => {
  const architecture = format === "armnt" ? "ARMNT" : "ARM64";
  return {
    chainedLabel: "Chained entries", handlerLabel: `Handlers present (${architecture} X bit)`,
    introNote: `${architecture} .pdata stores packed unwind data or points to .xdata records used for ` +
      `stack unwinding and exception dispatch.`,
    renderFormatNote: format === "armnt" ? renderArmntDetails : renderNoFormatDetails,
    renderFormatStats: format === "armnt" ? renderArmntSummary : renderNoFormatDetails,
    unwindLabel: "Unique unwind descriptions (.xdata or packed .pdata)"
  };
};

const getUnknownProfile = (): ExceptionRenderProfile => ({
  chainedLabel: "Chained entries", handlerLabel: "Handlers present",
  introNote: "The exception-table format is unknown or unsupported for this machine.",
  renderFormatNote: renderNoFormatDetails, renderFormatStats: renderNoFormatDetails,
  unwindLabel: "Unique unwind descriptions"
});

const getNtRiscProfile = (): ExceptionRenderProfile => ({
  handlerLabel: "Resolved functions with exception handlers",
  introNote: "NT RISC .pdata stores full virtual addresses, inline handler metadata, and prolog boundaries.",
  renderFormatNote: renderNoFormatDetails, renderFormatStats: renderNtRiscStatistics,
  unwindLabel: "Inline function descriptions"
});

const getCeProfile = (): ExceptionRenderProfile => ({
  handlerLabel: "Functions with handler metadata",
  introNote: "Windows CE .pdata stores virtual function addresses and lengths in 16-bit or 32-bit instructions. " +
    "Associated handler metadata immediately precedes the function.",
  renderFormatNote: renderNoFormatDetails, renderFormatStats: renderCeExceptionStatistics,
  unwindLabel: "Inline function descriptions"
});

const getIa64Profile = (): ExceptionRenderProfile => ({
  introNote: "IA64 .pdata stores three 32-bit image-relative addresses for each code range and its unwind data. " +
    "Recognized Windows unwind records are summarized by operation. Each unique block is counted once; " +
    "language-specific handler data is not decoded.",
  renderFormatNote: renderNoFormatDetails, renderFormatStats: renderIa64UnwindStatistics,
  unwindLabel: "Unique mapped unwind references"
});

const getLegacyProfile = (format: NonNullable<PeExceptionFormat>): ExceptionRenderProfile | undefined => {
  if (format === "ia64") return getIa64Profile();
  if (format === "ce") return getCeProfile();
  if (format === "nt-risc32" || format === "nt-risc64") return getNtRiscProfile();
  return undefined;
};

const getExceptionRenderProfile = (format: PeExceptionFormat): ExceptionRenderProfile => {
  if (format == null) return getUnknownProfile();
  const legacy = getLegacyProfile(format);
  if (legacy) return legacy;
  if (format === "native-aot-x86") {
    return {
      chainedLabel: "Chained entries",
      handlerLabel: "Handlers present",
      introNote:
        "NativeAOT x86 uses 12-byte RuntimeFunction rows with BeginAddress, " +
        "EndAddress, and an x86 UNWIND_INFO RVA.",
      renderFormatNote: renderNoFormatDetails,
      renderFormatStats: renderNoFormatDetails,
      unwindLabel: "Unique x86 UNWIND_INFO blocks"
    };
  }
  if (format === "ready-to-run-x86") {
    return {
      chainedLabel: "Chained entries",
      handlerLabel: "Exception clauses",
      introNote:
        "ReadyToRun x86 uses 8-byte RuntimeFunction rows with code start and x86 " +
        "unwind/GC-info RVAs; the row has no explicit end RVA.",
      renderFormatNote: renderNoFormatDetails,
      renderFormatStats: renderReadyToRunStats,
      unwindLabel: "Unique unwind blobs"
    };
  }
  if (format === "arm64" || format === "armnt") return getArmProfile(format);
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
      `${ex.functionCount} function${(ex.functionCount) === 1 ? "" : "s"}`
    )
  );
  out.push(`<div class="smallNote">${profile.introNote}</div>`);
  out.push(`<dl class="peExceptionStats">`);
  out.push(`<dt>Functions (RUNTIME_FUNCTION entries)</dt><dd>${ex.functionCount}</dd>`);
  out.push(`<dt>${profile.unwindLabel}</dt><dd>${ex.uniqueUnwindInfoCount}</dd>`);
  profile.renderFormatStats(ex, out);
  if (profile.handlerLabel) out.push(`<dt>${profile.handlerLabel}</dt><dd>${ex.handlerUnwindInfoCount}</dd>`);
  if (profile.chainedLabel) out.push(`<dt>${profile.chainedLabel}</dt><dd>${ex.chainedUnwindInfoCount}</dd>`);
  out.push(`<dt>Missing/invalid ranges</dt><dd>${ex.invalidEntryCount}</dd>`);
  out.push(`</dl>`);
  profile.renderFormatNote(ex, out);
  out.push(renderExceptionRangeHistogram(ex));
  if (ex.issues?.length) {
    out.push(renderPeDiagnostics("Exception directory warnings", ex.issues));
  }
  out.push(renderPeSectionEnd());
}
