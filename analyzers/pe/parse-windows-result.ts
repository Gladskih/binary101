"use strict";

import type { PeDebugSection, PeWindowsParseResult } from "./core/parse-result.js";
import { collectPeLayoutWarnings } from "./layout/warnings.js";
import type {
  PeDebugArtifacts,
  PeDirectoryArtifacts,
  PeImageArtifacts,
  PeWindowsParseContext
} from "./parse-windows.js";
import { attachManifestValidation } from "./resources/manifest-consistency.js";

const appendUniqueMessages = (existing: string[] | undefined, messages: string[]): string[] | undefined =>
  messages.length ? [...new Set([...(existing ?? []), ...messages])] : existing;

export const withWindowsPeLayoutWarnings = <T extends PeWindowsParseResult>(
  result: T,
  fileSize: number
): T => {
  const mergedWarnings = appendUniqueMessages(result.warnings, collectPeLayoutWarnings(result, fileSize));
  return mergedWarnings?.length ? { ...result, warnings: mergedWarnings } : result;
};

export const buildWindowsPeResult = (
  context: PeWindowsParseContext,
  debugArtifacts: PeDebugArtifacts,
  directories: PeDirectoryArtifacts,
  imageArtifacts: PeImageArtifacts,
  security: PeWindowsParseResult["security"],
  importLinking: PeWindowsParseResult["importLinking"]
): PeWindowsParseResult => {
  const { core } = context;
  const warnings = appendUniqueMessages(
    core.warnings,
    directories.manifestValidation?.warnings ?? []
  );
  return {
    debug: buildPeDebugSection(debugArtifacts),
    ...(debugArtifacts.coffDebug ? { coffDebug: debugArtifacts.coffDebug } : {}),
    dos: core.dos,
    signature: "PE",
    coff: core.coff,
    ...(directories.subtype ? { subtype: directories.subtype } : {}),
    ...(core.coffStringTableSize != null ? { coffStringTableSize: core.coffStringTableSize } : {}),
    ...(core.trailingAlignmentPaddingSize ? { trailingAlignmentPaddingSize: core.trailingAlignmentPaddingSize } : {}),
    opt: core.opt,
    ...(warnings?.length ? { warnings } : {}),
    dirs: core.dataDirs,
    sections: core.sections,
    entrySection: core.entrySection,
    rvaToOff: core.rvaToOff,
    imports: directories.importResult,
    loadcfg: directories.loadcfg,
    exports: directories.exportsInfo,
    tls: directories.tls,
    reloc: directories.reloc,
    msvcRtti: directories.msvcRtti,
    exception: directories.exception,
    boundImports: directories.boundImports,
    delayImports: directories.delayImports,
    clr: directories.clr,
    security,
    iat: directories.iat,
    importLinking,
    architecture: directories.architecture,
    globalPtr: directories.globalPtr,
    linuxBoot: context.linuxBoot,
    nativeAotCandidate: directories.nativeAotCandidate,
    ...(imageArtifacts.goRuntime ? { goRuntime: imageArtifacts.goRuntime } : {}),
    packers: imageArtifacts.packers,
    payloads: imageArtifacts.payloads,
    resources: attachManifestValidation(directories.resources, directories.manifestValidation),
    ...(imageArtifacts.overlay ? { overlay: imageArtifacts.overlay } : {}),
    imageEnd: core.imageEnd,
    imageSizeMismatch: core.imageSizeMismatch,
    hasCert: !!security?.count
  };
};

export const buildPeDebugSection = (
  debugArtifacts: PeDebugArtifacts
): PeDebugSection | null => {
  const { debugResult, debugNotes, debugWarning } = debugArtifacts;
  return debugResult.entry || debugWarning || debugNotes?.length || debugResult.entries.length
    ? {
        entry: debugResult.entry,
        ...(debugResult.entries.length ? { entries: debugResult.entries } : {}),
        ...(debugNotes?.length ? { notes: debugNotes } : {}),
        ...(debugResult.rawDataRanges.length ? { rawDataRanges: debugResult.rawDataRanges } : {}),
        ...(debugWarning ? { warning: debugWarning } : {})
      }
    : null;
};
