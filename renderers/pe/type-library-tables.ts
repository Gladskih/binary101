import { escapeHtml } from "../../html-utils.js";
import { variantTypeName } from "../../analyzers/pe/type-library/descriptors.js";
import type {
  TypeLibraryAnalysis, TypeLibraryCustomData, TypeLibraryValue
} from "../../analyzers/pe/type-library/types.js";

export const typeKindName = (kind: number): string =>
  ["enum", "record", "module", "interface", "dispinterface", "coclass", "alias", "union"][kind]
    ?? `TKIND(${kind})`;

export const libraryVersion = (version: number): string =>
  `${version & 0xffff}.${version >>> 16}`;

export const formatTypeLibraryFlags = (flags: number, names: readonly string[]): string => {
  const labels = names.filter((_, index) => flags & 2 ** index);
  return `${labels.join(", ")}${labels.length ? " " : ""}(0x${flags.toString(16)})`;
};

export const renderTypeLibraryTable = (
  caption: string, headers: readonly string[], rows: readonly (readonly unknown[])[]
): string => {
  if (!rows.length) return "";
  return `<div class="tableWrap"><table class="table"><caption>${escapeHtml(caption)}</caption>` +
    `<thead><tr>${headers.map(header => `<th scope="col">${escapeHtml(header)}</th>`).join("")}` +
    `</tr></thead><tbody>${rows.map(row => `<tr>${row.map(cell =>
      `<td${typeof cell === "number" ? ` class="peNumeric"` : ""}>` +
      `${escapeHtml(cell == null ? "—" : String(cell))}</td>`).join("")}</tr>`).join("")}` +
    `</tbody></table></div>`;
};

export const formatLibraryValue = (value: TypeLibraryValue | null): string =>
  value ? `${variantTypeName(value.type)}: ${value.value ?? "null / unavailable"}` : "—";

export const renderCustomData = (values: readonly TypeLibraryCustomData[]): string =>
  renderTypeLibraryTable("Custom data", ["GUID", "Value"],
    values.map(entry => [entry.guid, formatLibraryValue(entry.value)]));

export const resolveTypeLibraryReference = (
  analysis: TypeLibraryAnalysis, reference: number
): string => {
  if ((reference & 3) === 0) {
    return analysis.types.find(type => type.reference === reference)?.name ?? `href(${reference})`;
  }
  const imported = analysis.importedTypes.find(type => type.offset === (reference & ~3));
  return imported ? `${analysis.imports.find(entry =>
    entry.offset === imported.libraryOffset)?.name ?? "import"}: ${imported.identifier ?? "unknown type"}`
    : `href(${reference})`;
};

export const resolveTypeLibraryDescription = (
  analysis: TypeLibraryAnalysis, description: string
): string => description.replace(/href\((-?\d+)\)/g, (_, reference: string) =>
  resolveTypeLibraryReference(analysis, Number(reference)));
