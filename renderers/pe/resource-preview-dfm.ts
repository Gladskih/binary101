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

const componentFace = (node: DfmComponent): string => {
  const label = escapeHtmlText(textProperty(node, "Caption") || textProperty(node, "Text") || node.name);
  if (node.className === "TCheckBox") return `${textProperty(node, "Checked") === "true" ? "☑" : "☐"} ${label}`;
  if (node.className === "TRadioButton") return `◯ ${label}`;
  if (node.className === "TProgressBar") return `<progress value="${numberProperty(node, "Position", 0)}" ` +
    `max="${Math.max(1, numberProperty(node, "Max", 100))}"></progress>`;
  if (node.className === "TComboBox") return `${label} ▾`;
  return label;
};

export const renderDfmPreview = (root: DfmComponent): string => {
  const stack = [{ node: root, x: 0, y: 0, parent: "" }];
  const rows: string[] = [];
  const controls: string[] = [];
  while (stack.length) {
    const item = stack.pop()!;
    const node = item.node;
    const x = item.x + numberProperty(node, "Left", 0);
    const y = item.y + numberProperty(node, "Top", 0);
    const path = item.parent ? `${item.parent}.${node.name}` : node.name;
    rows.push(`<tr><td>${escapeHtmlText(path)}</td><td>${escapeHtmlText(node.className)}</td><td>` +
      node.properties.map(prop => `<div><b>${escapeHtmlText(prop.name)}</b>: ` +
        `${escapeHtmlText(propertyValue(prop.value))}</div>`).join("") + `</td></tr>`);
    if (node !== root) controls.push(`<div class="peDfm__control" ` +
      `title="${escapeHtmlText(`${path}: ${node.className}`)}" style="left:${x}px;top:${y}px;` +
      `width:${Math.max(0, numberProperty(node, "Width", 80))}px;` +
      `height:${Math.max(0, numberProperty(node, "Height", 24))}px">${componentFace(node)}</div>`);
    for (let index = node.children.length - 1; index >= 0; index -= 1) {
      stack.push({ node: node.children[index]!, x: node === root ? 0 : x,
        y: node === root ? 0 : y, parent: path });
    }
  }
  return `<p>DFM ${escapeHtmlText(root.name)} (${escapeHtmlText(root.className)}). ` +
    `Saved geometry; custom components, inherited forms and runtime layout may differ.</p>` +
    `<div class="peDfm"><div class="peDfm__form" style="width:${Math.max(1,
      numberProperty(root, "ClientWidth", numberProperty(root, "Width", 400)))}px;` +
    `height:${Math.max(1, numberProperty(root, "ClientHeight", numberProperty(root, "Height", 240)))}px">` +
    `${controls.join("")}</div></div><table class="table"><thead><tr><th>Component</th><th>Class</th>` +
    `<th>Saved properties</th></tr></thead><tbody>${rows.join("")}</tbody></table>`;
};
