import type { ResourceXmlTreeNode } from "../../analyzers/pe/resources/preview/types.js";
import { escapeHtmlText } from "../../html-utils.js";
import { ribbonChild, ribbonChildren, ribbonValue, ribbonCommandKey, renderRibbonElements } from "./ribbon-elements.js";
import type { ResourcePreviewContext } from "./resource-preview-context.js";

const categoryPanels = (
  category: ResourceXmlTreeNode, root: ResourceXmlTreeNode, context?: ResourcePreviewContext
): string => {
  const pools = { small: ribbonChild(category, "IMAGE_SMALL") ?? ribbonChild(root, "IMAGE"),
    large: ribbonChild(category, "IMAGE_LARGE") };
  const elements = renderRibbonElements(ribbonChildren(ribbonChild(category, "ELEMENTS"), "ELEMENT"),
    pools, context);
  const panels = ribbonChildren(ribbonChild(category, "PANELS"), "PANEL").map(panel =>
    `<section class="peRibbon__panel"><div class="peRibbon__panelElements">` +
    renderRibbonElements(ribbonChildren(ribbonChild(panel, "ELEMENTS"), "ELEMENT"), pools, context) +
    `</div><footer>${escapeHtmlText(ribbonValue(panel, "NAME") ?? "Panel")}</footer></section>`);
  return elements + panels.join("");
};

const quickAccessElements = (root: ResourceXmlTreeNode): ResourceXmlTreeNode[] => {
  const commands = new Map<number | string, ResourceXmlTreeNode>();
  const stack = [root];
  while (stack.length) {
    const node = stack.pop()!;
    if (node.name === "ELEMENT" || node.name === "BUTTON_MAIN") {
      const key = ribbonCommandKey(node);
      if (key !== null && !commands.has(key)) commands.set(key, node);
    }
    for (let index = node.children.length - 1; index >= 0; index -= 1) stack.push(node.children[index]!);
  }
  return ribbonChildren(ribbonChild(ribbonChild(root, "QAT_ELEMENTS"), "ITEMS"), "ITEM")
    .filter(item => ribbonValue(item, "VISIBLE") !== "FALSE").map(item => {
      const key = ribbonCommandKey(item);
      return key !== null && commands.has(key) ? commands.get(key)! : {
        name: "ELEMENT", attributes: [], text: null,
        children: [{ name: "TEXT", attributes: [], text: `Command ${key ?? "?"}`, children: [] }]
      };
    });
};

export const renderResourceRibbonBar = (
  root: ResourceXmlTreeNode, context?: ResourcePreviewContext
): string => {
  const categories = ribbonChildren(ribbonChild(root, "CATEGORIES"), "CATEGORY");
  const contexts = ribbonChildren(ribbonChild(root, "CONTEXTS"), "CONTEXT");
  const tabs = [...categories.map(node => ({ node, context: null as string | null })),
    ...contexts.flatMap(group => ribbonChildren(ribbonChild(group, "CATEGORIES"), "CATEGORY")
      .map(node => ({ node, context: ribbonValue(group, "TEXT") ?? ribbonValue(group, "NAME") ?? "Context" })))];
  const pools = { small: ribbonChild(root, "IMAGE") };
  const main = ribbonChild(root, "CATEGORY_MAIN");
  const mainButton = ribbonChild(root, "BUTTON_MAIN");
  return `<div class="peRibbon" data-pe-ribbon>` +
    `<p class="smallNote">Approximate resource layout; runtime additions and command state are unavailable. ` +
    `Expand a control to inspect its saved properties.</p>` +
    `<div class="peRibbon__quick">${renderRibbonElements(quickAccessElements(root), pools, context)}</div>` +
    `<div class="peRibbon__tabs" role="tablist" aria-label="Ribbon categories">` +
    (main ? `<details class="peRibbon__application"><summary>${escapeHtmlText(
      ribbonValue(mainButton, "TEXT") ?? "File")}</summary><div class="peRibbon__popup">` +
      categoryPanels(main, root, context) + `</div></details>` : "") +
    tabs.map((tab, index) => `<button type="button" role="tab" data-pe-ribbon-tab="${index}" ` +
      `aria-selected="${index === 0}" title="${escapeHtmlText(tab.context ?? "")}">` +
      `${escapeHtmlText(ribbonValue(tab.node, "NAME") ?? "Category")}` +
      `${tab.context ? `<small>${escapeHtmlText(tab.context)}</small>` : ""}</button>`).join("") +
    `</div>` + tabs.map((tab, index) => `<div role="tabpanel" data-pe-ribbon-panel="${index}" ` +
      `class="peRibbon__category"${index ? " hidden" : ""}>${categoryPanels(tab.node, root, context)}</div>`)
      .join("") +
    renderRibbonElements(ribbonChildren(ribbonChild(ribbonChild(root, "TAB_ELEMENTS"), "ELEMENTS") ??
      ribbonChild(root, "TAB_ELEMENTS"), "ELEMENT"), pools, context) + `</div>`;
};
