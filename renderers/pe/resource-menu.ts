import type { ResourceMenuItemPreview } from "../../analyzers/pe/resources/preview/types.js";
import { escapeHtml } from "../../html-utils.js";

const menuItemLabel = (item: ResourceMenuItemPreview): string => {
    return `<li>${item.text ? escapeHtml(item.text) : "(separator or unnamed)"}` +
      `${item.id == null ? "" : ` <span class="mono">#${item.id}</span>`}` +
      `${item.flags.length ? ` <span class="smallNote">${escapeHtml(item.flags.join(", "))}</span>` : ""}`;
};

export const renderMenuResourceItems = (items: ResourceMenuItemPreview[]): string => {
  if (!items.length) return '<div class="smallNote">(empty menu)</div>';
  const markup = ['<ul class="smallNote" style="padding-left:1.1rem;margin:.25rem 0 0 0">'];
  const stack: Array<ResourceMenuItemPreview | string> = ["</ul>"];
  for (let index = items.length - 1; index >= 0; index -= 1) stack.push(items[index]!);
  while (stack.length) {
    const item = stack.pop()!;
    if (typeof item === "string") { markup.push(item); continue; }
    markup.push(menuItemLabel(item));
    stack.push("</li>");
    if (item.children.length) {
      markup.push("<ul>"); stack.push("</ul>");
      for (let index = item.children.length - 1; index >= 0; index -= 1) stack.push(item.children[index]!);
    }
  }
  return markup.join("");
};
