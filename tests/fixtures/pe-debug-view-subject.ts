"use strict";

import type {
  PeCodeViewEntry,
  PeDebugDirectoryEntry,
  PePogoInfo,
  PeVcFeatureInfo
} from "../../analyzers/pe/debug/directory.js";
import type { PeWindowsParseResult } from "../../analyzers/pe/index.js";
import type { PeSection } from "../../analyzers/pe/types.js";
import {
  POGO_SIGNATURE_LTCG,
  POGO_SIGNATURE_NAME_LTCG,
  createPogoSubjectInfo,
  createSyntheticPdbPath,
  createVcFeatureSubjectInfo
} from "./pe-debug-payload-subject.js";
export { createSyntheticWarning } from "./pe-debug-payload-subject.js";
import {
  createPeSection,
  createPeWithSections
} from "./pe-renderer-headers-fixture.js";

// Upstream PE parsers model VC_FEATURE as five DWORD counters, so the canonical
// payload size is 20 bytes.
// https://raw.githubusercontent.com/saferwall/pe/main/debug.go
const DEBUG_VIEW_VC_FEATURE_SIZE = 0x14;
// Microsoft PE format debug types:
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#debug-type
const DEBUG_VIEW_TYPE_CODEVIEW = 2;
const DEBUG_VIEW_TYPE_VC_FEATURE = 12;
const DEBUG_VIEW_TYPE_POGO = 13;
const DEBUG_VIEW_TYPE_EMBEDDED_DEBUG = 17;

const createDebugRawRange = (entry: PeDebugDirectoryEntry) => ({
  start: entry.pointerToRawData,
  end: entry.pointerToRawData + entry.sizeOfData
});

const createSyntheticDebugSize = (type: number): number => type + 1;

const createSyntheticDebugPointer = (type: number, sizeOfData: number): number =>
  type + sizeOfData;

export const createDebugViewEntry = (
  type: number,
  addressOfRawData: number,
  pointerToRawData: number,
  sizeOfData = createSyntheticDebugSize(type)
): PeDebugDirectoryEntry => ({
  type,
  typeName: `TYPE_${type}`,
  sizeOfData,
  addressOfRawData,
  pointerToRawData
});

export const createDebugViewCodeView = (id = 0): PeCodeViewEntry => ({
  guid: `g-s${id.toString(36)}`,
  age: id,
  path: createSyntheticPdbPath(id)
});

export const createDebugViewVcFeature = (
  counters: Partial<PeVcFeatureInfo> = {}
): PeVcFeatureInfo => ({
  ...createVcFeatureSubjectInfo(),
  ...counters
});

export const createDebugViewPogo = (
  entries: PePogoInfo["entries"] = createPogoSubjectInfo().entries,
  signatureName = POGO_SIGNATURE_NAME_LTCG,
  signature = POGO_SIGNATURE_LTCG
): PePogoInfo => ({
  signature,
  signatureName,
  entries
});

export const createPeWithDebugViewSection = (): PeWindowsParseResult =>
  createPeWithSections(createPeSection("S0"));

export const createMappedDebugViewEntry = (
  section: PeSection,
  type: number,
  rawOffset: number,
  sizeOfData = createSyntheticDebugSize(type)
): PeDebugDirectoryEntry => createDebugViewEntry(
  type,
  section.virtualAddress + rawOffset,
  section.pointerToRawData + rawOffset,
  sizeOfData
);

export const createSectionCoveredRawOnlyDebugViewEntry = (
  section: PeSection,
  type: number,
  rawOffset: number,
  sizeOfData = createSyntheticDebugSize(type)
): PeDebugDirectoryEntry => createDebugViewEntry(
  type,
  0,
  section.pointerToRawData + rawOffset,
  sizeOfData
);

export const createDebugViewSection = (
  entries: PeDebugDirectoryEntry[],
  codeViewEntry: PeCodeViewEntry | null = null,
  warning: string | null = null
): NonNullable<PeWindowsParseResult["debug"]> => ({
  entry: codeViewEntry,
  entries,
  rawDataRanges: entries.map(createDebugRawRange),
  ...(warning ? { warning } : {})
});

export const createSequentialDebugViewSection = (types: number[]) =>
  createDebugViewSection(
    types.map((type, index) =>
      createDebugViewEntry(
        type,
        0,
        createSyntheticDebugPointer(type, index + 1)
      )
    )
  );

export const createRepeatedDebugViewSection = (type: number, count: number) =>
  createSequentialDebugViewSection(Array.from({ length: count }, () => type));

// Microsoft PE + LLVM-supported debug type ids used by renderers/pe/debug-type-info.ts:
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#debug-directory-image-only
// https://llvm.org/doxygen/BinaryFormat_2COFF_8h_source.html
export const createSupportedDebugViewTypes = (): number[] => [
  0, 1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 19, 20
];

export const createSupportedDebugViewSection = () =>
  createSequentialDebugViewSection(createSupportedDebugViewTypes());

export const createUnknownDebugViewType = (): number => 0xff;

export const createRepeatedPogoDebugViewSection = () =>
  createRepeatedDebugViewSection(DEBUG_VIEW_TYPE_POGO, 2);

export const createInconsistentEmbeddedDebugViewSection = (section: PeSection) =>
  createDebugViewSection([
    createSectionCoveredRawOnlyDebugViewEntry(section, DEBUG_VIEW_TYPE_EMBEDDED_DEBUG, 0)
  ]);

export const createMappedCodeViewDebugViewSection = (
  section: PeSection,
  codeView: PeCodeViewEntry,
  warning: string
) => createDebugViewSection([{
  ...createMappedDebugViewEntry(section, DEBUG_VIEW_TYPE_CODEVIEW, 0),
  codeView
}], codeView, warning);

export const createUnresolvedDebugViewSection = () =>
  createDebugViewSection([createDebugViewEntry(createUnknownDebugViewType(), 0, 0, 0)]);

export const createDecodedDebugViewSection = () => {
  const pogo = createDebugViewPogo();
  return {
    pogo,
    debug: createDebugViewSection([
      createVcFeatureDebugViewEntry(createDebugViewVcFeature()),
      createPogoDebugViewEntry(pogo)
    ])
  };
};

export const createVcFeatureDebugViewEntry = (
  feature: PeVcFeatureInfo,
  pointerToRawData = createSyntheticDebugPointer(
    DEBUG_VIEW_TYPE_VC_FEATURE,
    DEBUG_VIEW_VC_FEATURE_SIZE
  )
): PeDebugDirectoryEntry => ({
  ...createDebugViewEntry(
    DEBUG_VIEW_TYPE_VC_FEATURE,
    0,
    pointerToRawData,
    DEBUG_VIEW_VC_FEATURE_SIZE
  ),
  vcFeature: feature
});

export const createPogoDebugViewEntry = (
  pogo: PePogoInfo,
  pointerToRawData = createSyntheticDebugPointer(
    DEBUG_VIEW_TYPE_POGO,
    pogo.entries.length + pogo.signatureName.length
  )
): PeDebugDirectoryEntry => ({
  ...createDebugViewEntry(
    DEBUG_VIEW_TYPE_POGO,
    0,
    pointerToRawData,
    pogo.entries.length + pogo.signatureName.length
  ),
  pogo
});
