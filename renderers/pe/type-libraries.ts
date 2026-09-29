import type { PeResources } from "../../analyzers/pe/resources/index.js";
import type { ResourceTypeLibraryPreview } from "../../analyzers/pe/resources/preview/types.js";
import type { TypeLibraryExportAnalysis } from
  "../../analyzers/pe/resources/type-library-export-links.js";
import type { TypeLibraryRegistrationLink } from
  "../../analyzers/pe/resources/type-library-registry-links.js";
import type { TypeLibraryAnalysis, TypeLibraryType } from "../../analyzers/pe/type-library/types.js";
import { escapeHtml } from "../../html-utils.js";
import { renderPeSectionStart, renderPeSectionEnd } from "./collapsible-section.js";
import { renderTypeLibraryPreview } from "./resource-preview-type-library.js";
import { renderTypeLibraryMembers } from "./type-library-members.js";
import {
  formatTypeLibraryFlags, libraryVersion, renderCustomData, renderTypeLibraryTable,
  resolveTypeLibraryDescription, typeKindName
} from "./type-library-tables.js";

const renderType = (analysis: TypeLibraryAnalysis, type: TypeLibraryType): string =>
  `<details><summary>${escapeHtml(typeKindName(type.kind))} ${escapeHtml(type.name ?? "?")}` +
  ` — ${type.functions.length} functions, ${type.variables.length} variables</summary>` +
  renderTypeLibraryTable("Type attributes", ["Attribute", "Value"], [
    ["GUID", type.guid], ["Version", libraryVersion(type.version)],
    ["Flags", formatTypeLibraryFlags(type.flags, ["appobject", "cancreate", "licensed",
      "predeclid", "hidden", "control", "dual", "nonextensible", "oleautomation",
      "restricted", "aggregatable", "replaceable", "dispatchable", "reversebind", "proxy"])],
    ["Size (bytes)", type.size], ["Alignment", type.alignment],
    ["Vtable size (bytes)", type.vtableSize], ["Documentation", type.documentation],
    ["Help context", type.helpContext],
    ["Help string context", type.helpStringContext],
    ["Alias target", type.alias ? resolveTypeLibraryDescription(analysis, type.alias) : null],
    ["DLL", type.dll]
  ]) + renderCustomData(type.customData) + renderTypeLibraryMembers(analysis, type) + `</details>`;

const renderAnalysis = (library: ResourceTypeLibraryPreview): string => {
  const analysis = library.analysis;
  if (!analysis) return renderTypeLibraryPreview(library);
  return renderTypeLibraryTable("Library", ["Attribute", "Value"], [
    ["Format", library.format], ["Name", analysis.name], ["LIBID", analysis.guid],
    ["Documentation", analysis.documentation], ["Help file", analysis.helpFile],
    ["Help string DLL", analysis.helpStringDll],
    ["Help context", analysis.helpContext], ["Help string context", analysis.helpStringContext],
    ...library.headerFields.filter(field => ["Library version", "LCID", "Flags", "SYSKIND"]
      .includes(field.label)).map(field => [field.label,
      field.label === "Library version" && library.format === "MSFT"
        ? libraryVersion(Number(field.value)) : field.value])
  ]) + `<p class="smallNote">Text encoding is inferred from LCID; the original ANSI codepage ` +
    `is not declared. Referenced libraries are described locally and are not loaded.</p>` +
    renderTypeLibraryTable("Imported libraries", ["File", "LIBID", "LCID", "Version"],
      analysis.imports.map(entry => [entry.name, entry.guid,
        `0x${entry.lcid.toString(16)}`, libraryVersion(entry.version)])) +
    renderTypeLibraryTable("Imported types", ["Reference offset", "Library offset", "Kind", "GUID / index"],
      analysis.importedTypes.map(entry => [entry.offset, entry.libraryOffset,
        entry.flags === null ? "Not recorded" : typeKindName(entry.flags >>> 24), entry.identifier])) +
    renderCustomData(analysis.customData) +
    renderTypeLibraryTable("Types", ["Name", "Kind", "GUID", "Version", "Functions", "Variables"],
      analysis.types.map(type => [type.name, typeKindName(type.kind), type.guid,
        libraryVersion(type.version), type.functions.length, type.variables.length])) +
    analysis.types.map(type => renderType(analysis, type)).join("") +
    `<details><summary>Binary header and segment directory</summary>` +
    renderTypeLibraryPreview(library) + `</details>`;
};

const renderExportAnalysis = (analysis: TypeLibraryExportAnalysis): string =>
  renderTypeLibraryTable("DLL entry cross-check",
    ["Library", "Module function", "Declared entry", "PE export ordinal"],
    analysis.matches.map(match => [match.library, `${match.module}.${match.function}`,
      match.entry, match.ordinal])) +
  (analysis.warnings.length ? `<ul class="smallNote">${analysis.warnings.map(warning =>
    `<li>${escapeHtml(warning)}</li>`).join("")}</ul>` : "");

export const renderTypeLibraries = (
  resources: PeResources | null | undefined,
  exportAnalysis: TypeLibraryExportAnalysis = { matches: [], warnings: [] },
  registrationLinks: TypeLibraryRegistrationLink[] = []
): string => {
  const groups = resources?.detail?.filter(group => group.typeName === "TYPELIB") ?? [];
  if (!groups.length) return "";
  return renderPeSectionStart("Type libraries (COM)") +
    groups.flatMap(group => group.entries.flatMap(entry => entry.langs.map(lang =>
    `<article><h3>TYPELIB ${escapeHtml(entry.name ?? String(entry.id ?? "?"))}` +
    ` — language ${escapeHtml(String(lang.lang ?? "?"))}</h3>` +
    (lang.typeLibrary ? renderAnalysis(lang.typeLibrary)
      : `<p>Type library could not be decoded.</p>`) +
    (lang.previewIssues?.length ? `<ul class="smallNote">${lang.previewIssues.map(issue =>
      `<li>${escapeHtml(issue)}</li>`).join("")}</ul>` : "") + `</article>`
  ))).join("") + renderExportAnalysis(exportAnalysis) +
    renderTypeLibraryTable("Embedded COM registrations",
      ["Library", "Kind", "Contract", "GUID", "RGS resource"],
      registrationLinks.map(link => [link.library, link.kind, link.name,
        link.guid, link.registryResource])) + renderPeSectionEnd();
};
