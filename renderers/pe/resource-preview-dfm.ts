import type { DfmComponent } from "../../analyzers/pe/resources/preview/dfm.js";
import type { DfmValue } from "../../analyzers/pe/resources/preview/dfm-values.js";
import { escapeHtmlText } from "../../html-utils.js";

const property = (node: DfmComponent, name: string): DfmValue | undefined =>
  node.properties.find(item => item.name === name)?.value;
const textProperty = (node: DfmComponent, name: string): string => {
  const value = property(node, name);
  return value && "value" in value ? String(value.value) : "";
};
const numberProperty = (node: DfmComponent, name: string, fallback: number): number => {
  const value = property(node, name);
  return value?.kind === "number" && Number.isFinite(Number(value.value)) ? Number(value.value) : fallback;
};

const propertyValue = (value: DfmValue): string => {
  if (value.kind === "extended") return `x87 extended, raw little-endian: ${value.value}`;
  if (value.kind === "binary") return `${value.data.length} bytes: ` +
    Array.from(value.data.subarray(0, 32), byte => byte.toString(16).padStart(2, "0")).join(" ") +
    (value.data.length > 32 ? " …" : "");
  if (value.kind === "null") return "nil";
  if (value.kind === "set") return value.values.join(", ");
  if (value.kind === "list") return `${value.values.length} list items`;
  if (value.kind === "collection") return `${value.items.length} collection items`;
  return String(value.value);
};

const controlKinds = new Map(Object.entries({
  TLabel: "label", TStaticText: "label", TNewStaticText: "label",
  TButton: "button", TNewButton: "button", TBitBtn: "button", TSpeedButton: "button",
  TCheckBox: "checkbox", TNewCheckBox: "checkbox",
  TRadioButton: "radio", TNewRadioButton: "radio",
  TProgressBar: "progress", TNewProgressBar: "progress",
  TComboBox: "combo", TNewComboBox: "combo",
  TEdit: "edit", TNewEdit: "edit", TNewPathEdit: "edit",
  TMemo: "memo", TNewMemo: "memo", TRichEditViewer: "memo",
  TPanel: "panel", TGroupBox: "group",
  TBevel: "bevel", TImage: "image", TBitmapImage: "image",
  TNewNotebook: "notebook", TNewNotebookPage: "page"
}));

const controlKind = (node: DfmComponent): string => controlKinds.get(node.className) ??
  (node.children.length ? "container" : property(node, "Width") || property(node, "Height")
    ? "unknown" : "nonvisual");

const caption = (node: DfmComponent): string =>
  escapeHtmlText(textProperty(node, "Caption") || textProperty(node, "Text"));

const progressFace = (node: DfmComponent): string => {
  const minimum = numberProperty(node, "Min", 0);
  const range = numberProperty(node, "Max", 100) - minimum;
  const maximum = Number.isFinite(range) ? Math.max(1, range) : 1;
  const position = Math.min(maximum, Math.max(0, numberProperty(node, "Position", 0) - minimum));
  return `<progress value="${position}" max="${maximum}" aria-label="Progress"></progress>`;
};

const memoFace = (node: DfmComponent): string => {
  const lines = property(node, "Lines.Strings");
  return lines?.kind === "list" ? lines.values.map(value =>
    value.kind === "string" ? escapeHtmlText(value.value) : "").join("\n") : caption(node);
};

const controlFaces: Readonly<Record<string, (node: DfmComponent) => string>> = {
  button: caption, label: caption, panel: caption, edit: caption,
  memo: memoFace,
  checkbox: node => `${textProperty(node, "Checked") === "true" ? "&#x2611;" : "&#x2610;"} ${caption(node)}`,
  radio: node => `${textProperty(node, "Checked") === "true" ? "&#x25c9;" : "&#x25cb;"} ${caption(node)}`,
  combo: node => `${caption(node)} <span class="peDfm__arrow">&#x25be;</span>`,
  progress: progressFace,
  group: node => `<span class="peDfm__legend">${caption(node)}</span>`,
  image: () => `<span class="peDfm__image" aria-label="Image unavailable">&#x25a7;</span>`,
  unknown: node => escapeHtmlText(node.name)
};

const cssString = (value: string): string => `"${value.replace(/["\\\n\r\f\0]/gu,
  character => `\\${character.charCodeAt(0).toString(16)} `)}"`;

// CSS absolute lengths: 96px = 72pt. https://www.w3.org/TR/css-values-4/#absolute-lengths
const fontSize = (node: DfmComponent): number =>
  Math.abs(numberProperty(node, "Font.Height", 0)) || numberProperty(node, "Font.Size", 0) * 4 / 3;

const fontStyle = (node: DfmComponent): string => {
  const family = textProperty(node, "Font.Name");
  // Negative VCL Font.Height specifies character height in pixels; positive is cell height.
  // https://docwiki.embarcadero.com/Libraries/en/Vcl.Graphics.TFont.Height
  const size = fontSize(node);
  const style = property(node, "Font.Style");
  const values = style?.kind === "set" ? style.values : null;
  return (family ? `font-family:${cssString(family)},sans-serif;` : "") +
    (Number.isFinite(size) && size > 0 ? `font-size:${size}px;` : "") +
    (values ? `font-weight:${values.includes("fsBold") ? "bold" : "normal"};` +
      `font-style:${values.includes("fsItalic") ? "italic" : "normal"};` : "");
};

const textAlignments = new Map(Object.entries({
  taCenter: "center", taRightJustify: "right", taLeftJustify: "left"
}));
const controlColors = new Map(Object.entries({
  clWindow: "var(--bg)", clBtnFace: "var(--card)", clWhite: "var(--pe-dfm-white)",
  clBlack: "var(--pe-dfm-black)"
}));
const textWrapping = new Map([["true", "pre-wrap"], ["false", "pre"]]);

const controlStyle = (node: DfmComponent): string => {
  const color = controlColors.get(textProperty(node, "Color"));
  const align = textAlignments.get(textProperty(node, "Alignment"));
  const wrap = textWrapping.get(textProperty(node, "WordWrap"));
  return fontStyle(node) + (color ? `background:${color};` : "") +
    (align ? `text-align:${align};` : "") +
    (wrap ? `white-space:${wrap};` : "") +
    (textProperty(node, "BorderStyle") === "bsNone" ? "border:0;" : "");
};

type DfmFrame = {
  node: DfmComponent;
  path: string;
  kind: string;
  width: number;
  height: number;
  activePage: string;
};
type DfmTask = DfmFrame | "close";

const childFrame = (node: DfmComponent, parent: DfmFrame): DfmFrame => {
  const kind = controlKind(node);
  // Inno notebook pages are alClient and do not stream Left/Top/Width/Height/Visible.
  // https://github.com/jrsoftware/issrc/blob/main/Components/NewNotebook.pas
  return { node, path: `${parent.path}.${node.name}`, kind,
    width: kind === "page" ? parent.width : Math.max(0,
      numberProperty(node, "Width", kind === "notebook" ? 150 : 80)),
    height: kind === "page" ? parent.height : Math.max(0,
      numberProperty(node, "Height", kind === "notebook" ? 150 : 24)),
    activePage: textProperty(parent.node, "ActivePage") };
};

const controlPosition = (frame: DfmFrame): string =>
  frame.kind === "form" || frame.kind === "page" ? "left:0px;top:0px;" :
    `left:${numberProperty(frame.node, "Left", 0)}px;top:${numberProperty(frame.node, "Top", 0)}px;`;

const renderControl = (frame: DfmFrame): string => {
  const { node, path, kind, width, height, activePage } = frame;
  const hidden = textProperty(node, "Visible") === "false" || kind === "page" && activePage !== node.name;
  const classes = kind === "form" ? "peDfm__form" : `peDfm__control peDfm__control--${kind}`;
  const bevel = node.className === "TBevel" ? textProperty(node, "Shape") : "";
  const style = `${controlPosition(frame)}width:${width}px;height:${height}px;${controlStyle(node)}`;
  return `<div class="${classes}" data-pe-dfm-component="${escapeHtmlText(node.name)}" ` +
    `data-pe-dfm-shape="${escapeHtmlText(bevel)}" title="${escapeHtmlText(`${path}: ${node.className}`)}" ` +
    `style="${escapeHtmlText(style)}"${hidden ? " hidden" : ""}` +
    `${textProperty(node, "Enabled") === "false" ? ' aria-disabled="true"' : ""}>` +
    (controlFaces[kind]?.(node) ?? "");
};

const propertyRow = (node: DfmComponent, path: string): string =>
  `<tr><td>${escapeHtmlText(path)}</td><td>${escapeHtmlText(node.className)}</td><td>` +
  node.properties.map(prop => `<div><b>${escapeHtmlText(prop.name)}</b>: ` +
    `${escapeHtmlText(propertyValue(prop.value))}</div>`).join("") + `</td></tr>`;

export const renderDfmPreview = (root: DfmComponent): string => {
  const stack: DfmTask[] = [{ node: root, path: root.name, kind: "form", activePage: "",
    width: Math.max(1, numberProperty(root, "ClientWidth", numberProperty(root, "Width", 400))),
    height: Math.max(1, numberProperty(root, "ClientHeight", numberProperty(root, "Height", 240))) }];
  const rows: string[] = [];
  const controls: string[] = [];
  while (stack.length) {
    const item = stack.pop()!;
    if (item === "close") { controls.push("</div>"); continue; }
    rows.push(propertyRow(item.node, item.path));
    controls.push(renderControl(item));
    stack.push("close");
    for (let index = item.node.children.length - 1; index >= 0; index -= 1) {
      stack.push(childFrame(item.node.children[index]!, item));
    }
  }
  return `<p>DFM ${escapeHtmlText(root.name)} (${escapeHtmlText(root.className)}). ` +
    `Saved layout; inherited forms and runtime captions, images or custom controls may differ.</p>` +
    `<div class="peDfm">${controls.join("")}</div>` +
    `<table class="table"><thead><tr><th>Component</th><th>Class</th>` +
    `<th>Saved properties</th></tr></thead><tbody>${rows.join("")}</tbody></table>`;
};
