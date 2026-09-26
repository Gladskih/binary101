import type { TypeLibraryAnalysis, TypeLibraryType } from "./types.js";

// MSFT HREFTYPE uses low bits for imported references; SLTG references are normalized to
// the same representation. Resolve against parsed identities, never a guessed table index.
// https://github.com/wine-mirror/wine/blob/master/dlls/oleaut32/typelib.h
export const validateTypeLibraryReferences = (
  analysis: TypeLibraryAnalysis, issues: string[]
): void => {
  const local = new Set(analysis.types.map(type => type.reference));
  const imported = new Set(analysis.importedTypes.map(type => type.offset));
  const libraries = new Set(analysis.imports.map(library => library.offset));
  const reportedIssues = new Set(issues);
  for (const type of analysis.importedTypes) {
    if (!libraries.has(type.libraryOffset)) {
      warn(issues, reportedIssues, "TYPELIB imported type refers to a missing library.");
    }
  }
  for (const type of analysis.types) {
    for (const reference of collectReferences(type)) {
      if (!((reference & 3) === 0 ? local.has(reference) : imported.has(reference & ~3))) {
        warn(issues, reportedIssues, `TYPELIB type reference ${reference} is unresolved.`);
      }
    }
  }
};

const collectReferences = (type: TypeLibraryType): number[] => [
  ...type.interfaces.map(entry => entry.reference),
  ...[type.alias, ...type.variables.map(member => member.type), ...type.functions.flatMap(member =>
    [member.type, ...member.parameters.map(parameter => parameter.type)])].flatMap(description =>
    Array.from((description ?? "").matchAll(/href\((-?\d+)\)/g), match => Number(match[1])))
];

const warn = (issues: string[], reportedIssues: Set<string>, message: string): void => {
  if (reportedIssues.has(message)) return;
  reportedIssues.add(message);
  issues.push(message);
};
