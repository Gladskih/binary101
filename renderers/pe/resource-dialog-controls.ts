import type { ResourceDialogControlPreview } from "../../analyzers/pe/resources/preview/types.js";
import { escapeHtmlText } from "../../html-utils.js";
import { resolvedPreview, resolvedResourceImage } from "./resource-preview-context.js";
import type { ResourcePreviewContext } from "./resource-preview-context.js";

const caption = (text: string): string => {
  const parts: string[] = [];
  for (let index = 0; index < text.length; index += 1) {
    if (text[index] !== "&" || index + 1 >= text.length) parts.push(escapeHtmlText(text[index]));
    else {
      index += 1;
      parts.push(text[index] === "&" ? "&amp;" : `<u>${escapeHtmlText(text[index])}</u>`);
    }
  }
  return parts.join("");
};

const controlImage = (control: ResourceDialogControlPreview, context?: ResourcePreviewContext): string => {
  if (control.title === null) return "";
  const image = resolvedResourceImage(context, (control.style & 0x1f) === 3
    ? ["GROUP_ICON"] : ["BITMAP"], control.title);
  return image ? `<img src="${image}" ` +
    `alt="${escapeHtmlText(control.title)}" />` : escapeHtmlText(control.title);
};

const initialStrings = (control: ResourceDialogControlPreview, context?: ResourcePreviewContext): string[] => {
  if (!context) return [];
  const entry = context.catalog.detail[context.source.group]?.entries[context.source.entry];
  const key = entry?.name ?? entry?.id;
  if (key == null) return [];
  const init = resolvedPreview(context, ["DLGINIT"], key)?.dialogInit;
  if (!init) return [];
  return init.entries.filter(item => item.controlId === control.id &&
    ([0x401, 0x403, 0x1234].includes(item.message))).map(item => {
    const end = item.data.indexOf(0);
    // DLGINIT does not declare an ANSI code page; preserve the renderer's explicit approximation.
    return new TextDecoder("windows-1252").decode(item.data.subarray(0, end < 0 ? item.data.length : end));
  });
};

const buttonContent = (control: ResourceDialogControlPreview): string => {
  const kind = control.style & 0xf; // BS_TYPEMASK; WinUser.h Button Styles.
  const text = caption(String(control.title ?? ""));
  if (kind === 7) return `<span class="peDialog__groupLabel">${text}</span>`;
  if ([2, 3, 5, 6].includes(kind)) return `<span aria-hidden="true">☐</span> ${text}`;
  if (kind === 4 || kind === 9) return `<span aria-hidden="true">◯</span> ${text}`;
  return text;
};

const staticContent = (control: ResourceDialogControlPreview, context?: ResourcePreviewContext): string => {
  if ([3, 14].includes(control.style & 0x1f)) return controlImage(control, context);
  return control.style & 0x80 ? escapeHtmlText(control.title ?? "") : caption(String(control.title ?? ""));
};
const listContent = (control: ResourceDialogControlPreview, context?: ResourcePreviewContext): string => {
  const items = initialStrings(control, context);
  return items.map(item => `<div>${escapeHtmlText(item)}</div>`).join("") +
    (control.kind.toUpperCase() === "LISTBOX" ? "" : `<span class="peDialog__arrow">&#x25be;</span>`);
};
const faces = new Map<string, (control: ResourceDialogControlPreview, context?: ResourcePreviewContext) => string>([
  ["STATIC", staticContent], ["BUTTON", buttonContent],
  ["EDIT", control => control.style & 0x20 ? "&bull;&bull;&bull;&bull;" : escapeHtmlText(control.title ?? "")],
  ["COMBOBOX", listContent], ["LISTBOX", listContent], ["COMBOBOXEX32", listContent],
  ["MSCTLS_PROGRESS32", () => '<span class="peDialog__progress"></span>'],
  ["MSCTLS_TRACKBAR32", () => '<span class="peDialog__track">&#x2500;&#x25cf;&#x2500;&#x2500;&#x2500;&#x2500;</span>'],
  ["SCROLLBAR", () => "&#x25c2; &#x25b0; &#x25b8;"]
]);
const controlContent = (control: ResourceDialogControlPreview, context?: ResourcePreviewContext): string =>
  faces.get(control.kind.toUpperCase())?.(control, context) ?? escapeHtmlText(control.title || control.kind);

const controlClass = (control: ResourceDialogControlPreview): string => {
  const kind = control.kind.toUpperCase();
  if (kind === "BUTTON") {
    const style = control.style & 0xf;
    if (style === 7) return "group";
    if ([2, 3, 4, 5, 6, 9].includes(style)) return "check";
    return style === 1 ? "defaultButton" : "button";
  }
  if (["EDIT", "LISTBOX"].includes(kind) || kind.includes("COMBOBOX")) return "input";
  if (kind === "STATIC") return [16, 17, 18].includes(control.style & 0x1f) ? "line" : "static";
  return "custom";
};

const controlLayout = (context: ResourcePreviewContext | undefined, index: number) => {
  const entry = context?.catalog.detail[context.source.group]?.entries[context.source.entry];
  const key = entry?.name ?? entry?.id;
  return key == null ? undefined : resolvedPreview(context, ["AFX_DIALOG_LAYOUT"], key)
    ?.dialogLayout?.controls[index];
};

const controlGeometry = (control: ResourceDialogControlPreview, index: number,
  context?: ResourcePreviewContext): string => {
  const layout = controlLayout(context, index);
  const left = `calc(${control.x} * var(--pe-dlu-x) + var(--pe-dialog-dx) * ${(layout?.moveX ?? 0) / 100})`;
  const top = `calc(${control.y} * var(--pe-dlu-y) + var(--pe-dialog-dy) * ${(layout?.moveY ?? 0) / 100})`;
  const width = `calc(${Math.max(0, control.width)} * var(--pe-dlu-x) + ` +
    `var(--pe-dialog-dx) * ${(layout?.sizeX ?? 0) / 100})`;
  const height = `calc(${Math.max(0, control.height)} * var(--pe-dlu-y) + ` +
    `var(--pe-dialog-dy) * ${(layout?.sizeY ?? 0) / 100})`;
  return `top:${top};width:${width};height:${height};--pe-control-x:${left};`;
};

const controlTextStyle = (control: ResourceDialogControlPreview): string => {
  const alignment = control.kind.toUpperCase() === "STATIC" ? control.style & 0x1f : 0;
  return `text-align:${alignment === 1 ? "center" : alignment === 2 ? "right" : "left"};` + `white-space:${control.kind.toUpperCase() === "EDIT" && !(control.style & 4) ? "nowrap" : "normal"}`;
};

export const renderDialogControl = (
  control: ResourceDialogControlPreview, index: number, context?: ResourcePreviewContext,
  tabOrder: number | null = null, direction: "ltr" | "rtl" = "ltr"
): string => {
  const klass = controlClass(control);
  // WS_VISIBLE and WS_DISABLED are descriptive; the inspector can also show hidden controls.
  return `<div role="button" tabindex="0" data-pe-dialog-control="${index}" ` +
    `data-pe-dialog-visible="${Boolean(control.style & 0x10000000)}" ` +
    `${tabOrder === null ? "" : `data-pe-dialog-tab-index="${tabOrder}" `}` +
    `aria-label="${escapeHtmlText(`${control.kind} #${control.id}: ${control.title ?? ""}`)}" ` +
    `class="peDialog__control peDialog__control--${klass}${control.style & 0x08000000
      ? " peDialog__control--disabled" : ""}" ` +
    `style="${direction === "rtl" ? "right" : "left"}:var(--pe-control-x);` +
    `${controlGeometry(control, index, context)}${controlTextStyle(control)}">` +
    `${controlContent(control, context)}</div>`;
};
