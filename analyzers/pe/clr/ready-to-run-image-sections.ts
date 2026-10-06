import type { PeClrReadyToRun, PeClrReadyToRunSection } from "./ready-to-run-types.js";
export const readyToRunImageSections = (data: PeClrReadyToRun): PeClrReadyToRunSection[] => {
  // ComponentAssemblies is image-wide: component core headers cannot nest other components.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/inc/readytorun.h
  const headers = new Set(data.sections.flatMap(section => section.decoded?.kind === "components"
    ? section.decoded.entries.flatMap(entry => entry.coreHeader ? [entry.coreHeader] : []) : []));
  return [...data.sections, ...[...headers].flatMap(header => header.sections)];
};
