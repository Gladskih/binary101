import type { PeSection } from "../../analyzers/pe/types.js";
import { peSectionNameValue } from "../../analyzers/pe/sections/name.js";

export const createDebugSectionNameLookup = (sections: readonly PeSection[]): (rva: number) => string => {
  const ranges = sections.map(section => ({
    start: section.virtualAddress,
    end: section.virtualAddress + Math.max(section.virtualSize, section.sizeOfRawData),
    name: peSectionNameValue(section.name) || "(unnamed section)"
  })).sort((left, right) => left.start - right.start);
  const maximumEnds: number[] = [];
  ranges.forEach((range, index) => maximumEnds.push(Math.max(maximumEnds[index - 1] ?? -Infinity, range.end)));
  // Prefix maximum ends keep normal lookups logarithmic and bound overlap searches.
  // Raw extents count too: PE permits initialized bytes beyond VirtualSize.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-table-section-headers
  return rva => {
    let low = 0;
    let high = ranges.length;
    while (low < high) {
      const middle = Math.floor((low + high) / 2);
      if (ranges[middle]!.start <= rva) low = middle + 1;
      else high = middle;
    }
    const names: string[] = [];
    for (let index = low - 1; index >= 0 && maximumEnds[index]! > rva; index--) {
      if (rva < ranges[index]!.end) names.push(ranges[index]!.name);
    }
    names.reverse();
    return names.length > 1 ? `${names.join(" / ")} (overlapping)` : names[0] ?? "(outside sections)";
  };
};
