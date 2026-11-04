import type { ResourceXmlTreeNode } from "../../analyzers/pe/resources/preview/types.js";
import { escapeHtmlText } from "../../html-utils.js";
import { resolvedPreview } from "./resource-preview-context.js";
import type { ResourcePreviewContext } from "./resource-preview-context.js";

export const ribbonChild = (node: ResourceXmlTreeNode | undefined, name: string) =>
  node?.children.find(item => item.name === name);
export const ribbonChildren = (node: ResourceXmlTreeNode | undefined, name: string) =>
  node?.children.filter(item => item.name === name) ?? [];
export const ribbonValue = (node: ResourceXmlTreeNode | undefined, name: string): string | null =>
  ribbonChild(node, name)?.text ?? null;

export const ribbonCommandKey = (node: ResourceXmlTreeNode): number | string | null => {
  const id = ribbonChild(node, "ID");
  return numericValue(id, "VALUE") ?? ribbonValue(id, "NAME");
};

export interface RibbonImagePools {
  small?: ResourceXmlTreeNode | undefined;
  large?: ResourceXmlTreeNode | undefined;
}

const numericValue = (node: ResourceXmlTreeNode | undefined, name: string): number | null => {
  const text = ribbonValue(node, name);
  return text !== null && /^-?\d+$/u.test(text) && Number.isSafeInteger(Number(text)) ? Number(text) : null;
};

export const ribbonImageUrl = (
  node: ResourceXmlTreeNode | undefined, context?: ResourcePreviewContext
): string | undefined => {
  const id = ribbonChild(node, "ID");
  const key = numericValue(id, "VALUE") ?? ribbonValue(id, "NAME");
  return key == null || key === 0 ? undefined : resolvedPreview(context, ["BITMAP", "PNG"], key)?.previewDataUrl;
};

const stripImage = (element: ResourceXmlTreeNode, pools: RibbonImagePools,
  context?: ResourcePreviewContext): string => {
  const large = numericValue(element, "INDEX_LARGE");
  const small = numericValue(element, "INDEX_SMALL");
  const useLarge = large !== null && large >= 0 && pools.large;
  const index = useLarge ? large : small;
  const size = useLarge ? 32 : 16;
  const image = ribbonImageUrl(size === 32 ? pools.large : pools.small, context);
  // MFC defaults: 16x16 small and 32x32 large image strips; afxribboninfo.cpp.
  // https://github.com/adzm/atlmfc/blob/master/src/mfc/afxribboninfo.cpp
  return image && index !== null && index >= 0 ? `<span class="peRibbon__image" ` +
    `style="width:${size}px;height:${size}px;background-image:url(${image});` +
    `background-position:-${index * size}px 0"></span>` : "";
};

const elementImage = (
  element: ResourceXmlTreeNode, pools: RibbonImagePools, context?: ResourcePreviewContext
): string => {
  const own = ribbonImageUrl(ribbonChild(element, "IMAGE"), context);
  if (own) return `<img class="peRibbon__ownImage" src="${own}" alt="" />`;
  return stripImage(element, pools, context);
};

const elementProperties = (element: ResourceXmlTreeNode): string => {
  const rows = element.children.filter(child => child.text !== null).map(child =>
    `<tr><th scope="row">${escapeHtmlText(child.name)}</th><td>${escapeHtmlText(child.text)}</td></tr>`);
  const command = ribbonChild(element, "ID");
  if (command) rows.unshift(`<tr><th scope="row">Command</th><td>` +
    `${escapeHtmlText(ribbonValue(command, "NAME") ?? "")} ` +
    `${escapeHtmlText(ribbonValue(command, "VALUE") ?? "")}</td></tr>`);
  return `<table class="table peRibbon__properties"><tbody>${rows.join("")}</tbody></table>`;
};

const elementItems = (element: ResourceXmlTreeNode): string => {
  const items = ribbonChildren(ribbonChild(element, "ITEMS"), "ITEM");
  const groups = ribbonChildren(ribbonChild(element, "GROUPS"), "GROUP");
  return (items.length ? `<ul>${items.map(item => `<li>${escapeHtmlText(item.text ?? "")}</li>`)
    .join("")}</ul>` : "") + groups.map(group => `<p>${escapeHtmlText(ribbonValue(group, "NAME") ?? "Gallery")}: ` +
    `${escapeHtmlText(ribbonValue(group, "ITEMS") ?? "0")} items</p>`).join("");
};

const faceSuffix = (kind: string, element: ResourceXmlTreeNode): string => {
  if (kind === "Edit") return `<span class="peRibbon__field">${escapeHtmlText(ribbonValue(element, "VALUE") ?? "")}</span>`;
  if (kind.startsWith("ComboBox")) return '<span class="peRibbon__field">&#x25be;</span>';
  return new Map([["Slider", "&#x2500;&#x25cf;&#x2500;&#x2500;&#x2500;&#x2500;"], ["Progress", "&#x25b0;&#x25b0;&#x25b1;&#x25b1;"]]).get(kind) ?? "";
};
const elementFace = (element: ResourceXmlTreeNode): string => {
  const kind = ribbonValue(element, "ELEMENT_NAME") ?? "Element";
  const text = escapeHtmlText(ribbonValue(element, "TEXT") ?? kind);
  if (kind === "Separator") return "<hr />";
  if (kind === "Button_Check") return `&#x2610; ${text}`;
  return `${text} ${faceSuffix(kind, element)}`;
};

export const renderRibbonElements = (
  elements: ResourceXmlTreeNode[], pools: RibbonImagePools, context?: ResourcePreviewContext
): string => {
  const markup: string[] = [];
  const stack: Array<{ element: ResourceXmlTreeNode; pools: RibbonImagePools } | string> =
    elements.slice().reverse().map(element => ({ element, pools }));
  while (stack.length) {
    const frame = stack.pop()!;
    if (typeof frame === "string") { markup.push(frame); continue; }
    const element = frame.element;
    const children = ribbonChildren(ribbonChild(element, "ELEMENTS"), "ELEMENT");
    const tooltip = ribbonValue(element, "TOOLTIP") ?? ribbonValue(element, "DESCRIPTION") ?? "";
    const keys = ribbonValue(element, "KEYS");
    markup.push(`<details class="peRibbon__element"><summary title="${escapeHtmlText(tooltip)}">` +
      `${elementImage(element, frame.pools, context)}<span>${elementFace(element)}</span>` +
      `${keys ? `<kbd>${escapeHtmlText(keys)}</kbd>` : ""}</summary>`);
    stack.push(elementItems(element) + elementProperties(element) + "</details>");
    if (children.length) {
      markup.push(`<div class="peRibbon__popup">`); stack.push("</div>");
      for (let index = children.length - 1; index >= 0; index -= 1) {
        stack.push({ element: children[index]!, pools: {
          small: ribbonChild(element, "IMAGE") ?? frame.pools.small, large: frame.pools.large } });
      }
    }
  }
  return markup.join("");
};
