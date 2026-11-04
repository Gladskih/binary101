"use strict";

import type { ResourceXmlTreeNode } from "../../analyzers/pe/resources/preview/types.js";
import { escapeHtml } from "../../html-utils.js";

const renderNodeText = (text: string | null): string =>
  text
    ? `<div class="mono smallNote" style="margin-top:.25rem;white-space:pre-wrap;word-break:break-word">${escapeHtml(text)}</div>`
    : "";

const renderAttributeList = (node: ResourceXmlTreeNode): string => {
  if (!node.attributes.length) return "";
  const items = node.attributes
    .map(attribute =>
      `<li><span class="mono">@${escapeHtml(attribute.name)}</span>: ${escapeHtml(attribute.value)}</li>`
    )
    .join("");
  return `<ul class="smallNote" style="padding-left:1.1rem;margin:.25rem 0 0 0">${items}</ul>`;
};

const renderNodeSummary = (node: ResourceXmlTreeNode): string => {
  const parts = [`<span class="mono">&lt;${escapeHtml(node.name)}&gt;</span>`];
  if (node.attributes.length) {
    parts.push(
      `<span class="smallNote">${node.attributes.length} attr${node.attributes.length === 1 ? "" : "s"}</span>`
    );
  }
  if (node.children.length) {
    parts.push(
      `<span class="smallNote">${node.children.length} child${node.children.length === 1 ? "" : "ren"}</span>`
    );
  } else if (node.text) parts.push('<span class="smallNote">text</span>');
  return parts.join(" ");
};

const renderXmlTreeNode = (node: ResourceXmlTreeNode, depth: number): string => {
  const markup: string[] = [];
  const stack: Array<{ node: ResourceXmlTreeNode; depth: number } | string> = [{ node, depth }];
  while (stack.length) {
    const frame = stack.pop()!;
    if (typeof frame === "string") { markup.push(frame); continue; }
    markup.push(`<details style="margin-top:${frame.depth ? ".25rem" : ".2rem"}"` +
      `${frame.depth === 0 ? " open" : ""}><summary style="cursor:pointer">` +
      `${renderNodeSummary(frame.node)}</summary>${renderAttributeList(frame.node)}` +
      renderNodeText(frame.node.text));
    stack.push("</details>");
    if (frame.node.children.length) {
      markup.push(`<div style="margin-top:.3rem;padding-left:.8rem;border-left:1px solid var(--border2)">`);
      stack.push("</div>");
      for (let index = frame.node.children.length - 1; index >= 0; index -= 1) {
        stack.push({ node: frame.node.children[index]!, depth: frame.depth + 1 });
      }
    }
  }
  return markup.join("");
};

const renderXmlTreeButton = (
  action: "expand" | "collapse",
  label: string,
  disabled: boolean
): string =>
  `<button type="button" data-manifest-tree-action="${action}"${disabled ? " disabled" : ""} ` +
  `style="cursor:${disabled ? "not-allowed" : "pointer"};opacity:${disabled ? ".55" : "1"};` +
  `padding:.15rem .45rem;border:1px solid var(--border2);border-radius:6px;` +
  `background:var(--chip-bg);color:var(--text)">${label}</button>`;

const renderXmlTree = (tree: ResourceXmlTreeNode | undefined): string => {
  if (!tree) return "";
  return `<section data-manifest-tree-viewer style="margin-top:.35rem;padding:.45rem .55rem;` +
    `border:1px solid var(--border2);border-radius:8px;background:var(--card)">` +
    `<div class="smallNote" style="display:flex;gap:.35rem;align-items:center;flex-wrap:wrap;` +
    `margin-top:.2rem"><span><b>Parsed XML tree</b></span>` +
    renderXmlTreeButton("expand", "Expand all", !tree.children.length) +
    renderXmlTreeButton("collapse", "Collapse all", false) +
    `</div><div data-manifest-tree style="margin-top:.2rem">${renderXmlTreeNode(tree, 0)}</div></section>`;
};

export const renderXmlPreview = (
  textPreview: string | undefined,
  tree: ResourceXmlTreeNode | undefined
): string => [
  renderXmlTree(tree),
  textPreview
    ? `<div class="mono smallNote" style="margin-top:.35rem;white-space:pre-wrap;word-break:break-word">` +
      `${escapeHtml(textPreview)}</div>`
    : ""
].join("");
