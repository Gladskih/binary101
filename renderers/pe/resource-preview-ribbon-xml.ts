"use strict";

import type { ResourceXmlTreeNode } from "../../analyzers/pe/resources/preview/types.js";
import { escapeHtml } from "../../html-utils.js";
import { renderXmlPreview } from "./resource-preview-xml.js";

// The MFC resource structure is visible in Microsoft's Ribbon Designer docs and
// the upstream Kerberos MFC sample's ribbon1.mfcribbon-ms.
// https://learn.microsoft.com/en-us/cpp/mfc/ribbon-designer-mfc
// https://github.com/krb5/krb5/commit/173d79e16765f73bcf0adec8b78d28a6038c305b
const child = (node: ResourceXmlTreeNode | undefined, name: string):
  ResourceXmlTreeNode | undefined => node?.children.find(item => item.name === name);

const children = (node: ResourceXmlTreeNode | undefined, name: string):
  ResourceXmlTreeNode[] => node?.children.filter(item => item.name === name) ?? [];

const value = (node: ResourceXmlTreeNode | undefined, name: string): string | null =>
  child(node, name)?.text ?? null;

interface RibbonRow { category: string; panel: string; control: string;
  label: string | null; command: string | null }

const rowsForElements = (
  node: ResourceXmlTreeNode | undefined, category: string, panel: string
): RibbonRow[] => children(child(node, "ELEMENTS"), "ELEMENT").map(element => ({
  category, panel, control: value(element, "ELEMENT_NAME") ?? "Element",
  label: value(element, "TEXT"), command: value(child(element, "ID"), "NAME") ??
    value(child(element, "ID"), "VALUE")
}));

const rowsForCategory = (category: ResourceXmlTreeNode): RibbonRow[] => {
  const name = value(category, "NAME") ?? (category.name === "CATEGORY_MAIN" ?
    "Application menu" : "(unnamed category)");
  const panels = children(child(category, "PANELS"), "PANEL");
  return [...rowsForElements(category, name, "–"), ...panels.flatMap(panel =>
    rowsForElements(panel, name, value(panel, "NAME") ?? "(unnamed panel)"))];
};

export const renderRibbonXmlPreview = (
  text: string | undefined, tree: ResourceXmlTreeNode | undefined
): string => {
  if (tree?.name !== "RIBBON_BAR") return renderXmlPreview(text, tree);
  const categories = [
    ...children(tree, "CATEGORY_MAIN"),
    ...children(child(tree, "CATEGORIES"), "CATEGORY")
  ];
  const rows = categories.flatMap(rowsForCategory);
  const button = child(tree, "BUTTON_MAIN");
  if (button) rows.unshift({ category: "Application button", panel: "–",
    control: value(button, "ELEMENT_NAME") ?? "Button",
    label: value(button, "TEXT"), command: value(child(button, "ID"), "NAME") });
  return `<p>MFC Ribbon: ${categories.length} categories, ${rows.length} controls.</p>` +
    (rows.length ? `<div style="overflow-x:auto"><table class="table peResourceNestedTable">` +
      `<thead><tr><th>Category</th><th>Panel</th><th>Control</th>` +
      `<th>Label</th><th>Command</th></tr></thead><tbody>` +
      rows.map(row => `<tr><td>${escapeHtml(row.category)}</td>` +
        `<td>${escapeHtml(row.panel)}</td><td>${escapeHtml(row.control)}</td>` +
        `<td>${escapeHtml(row.label ?? "–")}</td>` +
        `<td class="mono">${escapeHtml(row.command ?? "–")}</td></tr>`).join("") +
      `</tbody></table></div>` : "") + renderXmlPreview(text, tree);
};
