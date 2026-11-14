import type { PeWindowsParseResult } from "../../analyzers/pe/core/parse-result.js";

type Check = readonly [name: string, evidence: unknown];
const debugEntries = (pe: PeWindowsParseResult) => pe.debug?.entries ?? [];
const payload = (pe: PeWindowsParseResult, format: string) =>
  pe.payloads?.entries.some(entry => entry.format === format);
const codeViewEvidence = (pe: PeWindowsParseResult) =>
  pe.debug?.entry || pe.debug?.codeViewSources?.length ||
  debugEntries(pe).some(entry => entry.codeView || entry.legacyCodeView);
const readyToRunEvidence = (pe: PeWindowsParseResult) => {
  const header = pe.clr?.readyToRun ?? pe.readyToRun;
  return header?.status !== "absent" && header;
};

const runtimeChecks = (pe: PeWindowsParseResult): Check[] => [
  ["Go runtime metadata", pe.goRuntime],
  ["D runtime metadata", pe.dRuntime],
  [".NET apphost", pe.appHost],
  ["Linux boot protocol", pe.linuxBoot],
  ["NativeAOT", pe.nativeAotCandidate],
  ["MSVC C++ RTTI", pe.msvcRtti],
  ["Itanium C++ RTTI", pe.itaniumRtti],
  ["Microsoft-compatible exception handling", pe.msvcEh],
  ["Unexplained overlay", pe.overlay],
  ["ReadyToRun", readyToRunEvidence(pe)],
  ["CLR header", pe.clr]
];
const debugChecks = (pe: PeWindowsParseResult): Check[] => [
  ["CodeView debug information", codeViewEvidence(pe)],
  ["TD32 debug information", pe.debug?.td32Sources?.length ||
    debugEntries(pe).some(entry => entry.td32)],
  ["COFF debug information", pe.coffDebug || debugEntries(pe).some(entry => entry.coff)],
  ["COM type-library resources", pe.resources?.detail?.some(group => group.typeName === "TYPELIB")]
];
const payloadChecks = (pe: PeWindowsParseResult): Check[] => [
  ["PE images in resources", payload(pe, "pe")],
  ["RAR archives in overlay", payload(pe, "rar")],
  ["7z archives in overlay", payload(pe, "sevenzip")],
  ["Flash Projector", pe.payloads?.projectorCandidate || payload(pe, "swf")]
];

export const collectPeChecksWithoutFindings = (pe: PeWindowsParseResult): string[] =>
  [...runtimeChecks(pe), ...debugChecks(pe), ...payloadChecks(pe)]
    .filter(([, evidence]) => !evidence).map(([name]) => name);
