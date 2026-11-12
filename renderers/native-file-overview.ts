import type { ParseForUiResult } from "../analyzers/analyzer-types.js";
import { escapeHtmlText } from "../html-utils.js";
import { hex, humanSize } from "../binary-utils.js";
import { isPeWindowsParseResult } from "../analyzers/pe/core/parse-result.js";
import { getPeSanityIssues } from "./pe/layout.js";
import { overviewFact, renderOverviewCard } from "./overview-card.js";
import type { ResourceLangWithPreview } from "../analyzers/pe/resources/preview/types.js";

const resourceImage = (
  leaves: readonly { type: string; name: string | number; language: ResourceLangWithPreview }[]
): string => {
  const images = leaves.filter(leaf => leaf.language.previewDataUrl?.startsWith("data:image/"));
  // Prefer an embedded icon; otherwise choose the largest available image payload.
  const icons = images.filter(leaf => leaf.type === "ICON");
  const image = (icons.length ? icons : images).reduce<typeof leaves[number] | null>((left, right) =>
    !left || right.language.size > left.language.size ? right : left, null);
  if (!image) return "";
  const path = `${image.type} / ${image.name} / LANGID ` +
    (image.language.lang == null ? "?" : hex(image.language.lang, 4));
  return `<img class="workspaceCard__image" src="${escapeHtmlText(image.language.previewDataUrl!)}" ` +
    `alt="${escapeHtmlText(path)}" loading="lazy" decoding="async" />`;
};

const resourceHighlights = (result: Extract<ParseForUiResult, { analyzer: "pe" }>): string => {
  if (!isPeWindowsParseResult(result.parsed)) return "";
  const resources = result.parsed.resources;
  const leaves = resources?.detail.flatMap(group => group.entries.flatMap(entry =>
    entry.langs.map(language => ({ type: group.typeName, name: entry.name ?? entry.id ?? "?",
      language })))) ?? [];
  if (!leaves.length) return "";
  const values = leaves.flatMap(leaf => leaf.language.versionInfo?.stringValues ?? []);
  const facts = ["FileDescription", "FileVersion", "CompanyName"].flatMap(key => {
    const distinct = [...new Set(values.filter(value => value.key === key).map(value => value.value))];
    return distinct.length ? [overviewFact(key, distinct.length === 1 ? distinct[0]! :
      `${distinct.length} distinct values`)] : [];
  }).join("");
  const largest = leaves.reduce((left, right) =>
    right.language.size > left.language.size ? right : left);
  return resourceImage(leaves) +
    (facts || overviewFact("Largest resource", `${largest.type} / ${largest.name}`) +
      overviewFact("Size", humanSize(largest.language.size))) +
    (resources?.issues?.length ? overviewFact("Resource warnings", String(resources.issues.length)) : "");
};

const peOverview = (result: Extract<ParseForUiResult, { analyzer: "pe" }>): string => {
  const issues = getPeSanityIssues(result.parsed);
  return renderOverviewCard("Resources", "analysis-resources", resourceHighlights(result)) +
    (issues.length ? renderOverviewCard("Sanity", "analysis-sanity",
      overviewFact("Warnings", String(issues.length)) +
      overviewFact("First recorded warning", issues[0]!), "supplemental") : "");
};

const elfOverview = (result: Extract<ParseForUiResult, { analyzer: "elf" }>): string => {
  const elf = result.parsed;
  const out: string[] = [];
  if (elf.comment?.strings.length) out.push(renderOverviewCard(".comment", "analysis-debug",
    overviewFact("First string", elf.comment.strings[0]!) +
    overviewFact("Strings", String(elf.comment.strings.length))));
  const buildIds = elf.notes?.entries.filter(note => note.typeName === "NT_GNU_BUILD_ID") ?? [];
  if (buildIds.length) out.push(renderOverviewCard("NT_GNU_BUILD_ID", "analysis-notes",
    overviewFact("Value", buildIds[0]!.value ?? "Unavailable") +
    overviewFact("Source", buildIds[0]!.source)));
  if (elf.dynamic?.needed.length) out.push(renderOverviewCard("DT_NEEDED", "analysis-linking",
    overviewFact("First dependency", elf.dynamic.needed[0]!) +
    overviewFact("Dependencies", String(elf.dynamic.needed.length))));
  return out.join("");
};

export const renderNativeFileOverview = (result: ParseForUiResult): string => {
  if (result.analyzer === "pe") return peOverview(result);
  if (result.analyzer === "elf") return elfOverview(result);
  return "";
};
