
// PreProcessBuffer runs before parsing, including inside quoted strings. %% is literal %.
// PreProcessBuffer uses TCHAR buf[32]: 32 - 1 terminating NUL = 31 key characters.
// Its explicit >31 check enforces this; CExpansionVectorEqualHelper ignores case.
// https://github.com/adzm/atlmfc/blob/master/include/statreg.h
export const registryParameters = (text: string, issues: string[]): string[] => {
  const parameters = new Set<string>();
  let offset = 0;
  while (offset < text.length) {
    const start = text.indexOf("%", offset);
    if (start < 0) break;
    if (text[start + 1] === "%") { offset = start + 2; continue; }
    const end = text.indexOf("%", start + 1);
    if (end < 0) { issues.push("ATL RGS: unclosed replacement parameter."); break; }
    const name = text.slice(start + 1, end);
    if (name.length > 31) issues.push("ATL RGS: replacement name exceeds 31 characters.");
    parameters.add(name.toUpperCase());
    offset = end + 1;
  }
  return [...parameters];
};
