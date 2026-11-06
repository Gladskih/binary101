import type { ManifestXmlDocumentParser, ManifestXmlElement, ManifestXmlNode } from "./manifest-xml.js";
import { readXmlParserIssue } from "./manifest-xml.js";
import type { ResourcePreviewResult } from "./types.js";
import type { ResourceVectorNode } from "./vector-types.js";

// SVG 2 geometry/presentation attributes. Rebuild an inert drawing from known shapes;
// never insert source markup, CSS, script, href, foreignObject, or external references.
// https://www.w3.org/TR/SVG2/struct.html
const tags = new Set(["g", "path", "rect", "circle", "ellipse", "line", "polyline", "polygon", "text", "tspan"]);
const numeric = new Set(["x", "y", "x1", "y1", "x2", "y2", "width", "height", "rx", "ry", "cx", "cy", "r",
  "stroke-width", "opacity", "fill-opacity", "stroke-opacity", "font-size", "dx", "dy"]);
const numberPattern = /^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:e[+-]?\d+)?$/iu;

const attributePatterns = new Map<string, RegExp>([
  ["fill", /^(?:none|currentColor|transparent|[a-z]+|#[\da-f]{3,8}|(?:rgb|rgba|hsl|hsla)\([\d.% ,+-]+\))$/iu],
  ["d", /^[MmLlHhVvCcSsQqTtAaZz\d\s.,eE+-]*$/u],
  ["points", /^[\d\s.,eE+-]*$/u], ["stroke-dasharray", /^[\d\s.,eE+-]*$/u],
  // Keep each inter-transform whitespace run in one repetition (CodeQL js/redos).
  ["transform", /^\s*(?:(?:matrix|translate|scale|rotate|skewX|skewY)\([\d\s.,eE+-]+\)\s*)+$/u],
  ["font-family", /^[\p{L}\p{N} _,.-]+$/u], ["font-weight", /^(?:normal|bold|[1-9]00)$/u],
  ["font-style", /^(?:normal|italic|oblique)$/u], ["text-anchor", /^(?:start|middle|end)$/u],
  ["stroke-linecap", /^(?:butt|round|square)$/u], ["stroke-linejoin", /^(?:miter|round|bevel)$/u],
  ["fill-rule", /^(?:nonzero|evenodd)$/u]
]);
attributePatterns.set("stroke", attributePatterns.get("fill")!);

const safeAttribute = (name: string, value: string): boolean => numeric.has(name)
  ? numberPattern.test(value) && Number.isFinite(Number(value)) : attributePatterns.get(name)?.test(value) ?? false;

const styleAttributes = (style: string, omitted: Set<string>): ResourceVectorNode["attributes"] => {
  const attributes: ResourceVectorNode["attributes"] = [];
  for (const declaration of style.split(";")) {
    const split = declaration.indexOf(":");
    const name = declaration.slice(0, split).trim();
    const value = declaration.slice(split + 1).trim();
    if (split >= 0 && safeAttribute(name, value)) attributes.push({ name, value });
    else if (declaration.trim()) omitted.add("style declarations");
  }
  return attributes;
};

const copyAttributes = (node: ManifestXmlElement, omitted: Set<string>): ResourceVectorNode["attributes"] => {
  const attributes: ResourceVectorNode["attributes"] = [];
  for (const attribute of Array.from(node.attributes ?? [])) {
    if (attribute.name === "style") {
      attributes.push(...styleAttributes(attribute.value, omitted));
    } else if (safeAttribute(attribute.name, attribute.value.trim())) {
      attributes.push({ name: attribute.name, value: attribute.value.trim() });
    }
    else if (!["xmlns", "version", "viewBox"].includes(attribute.name)) omitted.add(`attribute ${attribute.name}`);
  }
  return attributes;
};

const appendTextNode = (source: ManifestXmlElement, child: ManifestXmlNode,
  target: ResourceVectorNode[]): boolean => {
  if (child.nodeType !== 3 && child.nodeType !== 4) return false;
  if (source.tagName === "text" || source.tagName === "tspan") {
    target.push({ tag: "tspan", attributes: [], text: child.nodeValue ?? "", children: [] });
  }
  return true;
};

const drawingNodes = (root: ManifestXmlElement, omitted: Set<string>): ResourceVectorNode[] => {
  const nodes: ResourceVectorNode[] = [];
  const stack = [{ source: root, target: nodes }];
  while (stack.length) {
    const frame = stack.pop()!;
    for (const childNode of Array.from(frame.source.childNodes ?? [])) {
      if (appendTextNode(frame.source, childNode, frame.target)) continue;
      if (childNode.nodeType !== 1) continue;
      const child = childNode as ManifestXmlElement;
      const tag = child.tagName;
      if (["title", "desc", "metadata"].includes(tag)) continue;
      if (!tags.has(tag)) { omitted.add(`element ${child.tagName}`); continue; }
      const node: ResourceVectorNode = { tag, attributes: copyAttributes(child, omitted),
        text: null, children: [] };
      frame.target.push(node);
      stack.push({ source: child, target: node.children });
    }
  }
  // Root presentation attributes also inherit into its shapes.
  const attributes = copyAttributes(root, omitted).filter(attribute =>
    !["x", "y", "width", "height"].includes(attribute.name));
  return attributes.length ? [{ tag: "g", attributes, text: null, children: nodes }] : nodes;
};

const drawingBounds = (root: ManifestXmlElement) => {
  const attributes = Array.from(root.attributes ?? []);
  const box = attributes.find(attribute => attribute.name === "viewBox")?.value.trim().split(/[\s,]+/u).map(Number);
  if (box?.length === 4 && box.every(Number.isFinite) && box[2]! > 0 && box[3]! > 0) {
    return { x: box[0]!, y: box[1]!, width: box[2]!, height: box[3]! };
  }
  const dimension = (name: string): number => {
    const value = attributes.find(attribute => attribute.name === name)?.value ?? "";
    return /^\d+(?:\.\d+)?(?:px)?$/u.test(value) && Number.isFinite(Number.parseFloat(value)) && Number.parseFloat(value) > 0
      ? Number.parseFloat(value) : 300;
  };
  return { x: 0, y: 0, width: dimension("width"), height: dimension("height") };
};

export const addSvgTextPreview = (
  text: string, parse: ManifestXmlDocumentParser
): ResourcePreviewResult | null => {
  if (!/^\s*(?:<\?xml[^>]*>\s*)?<svg[\s/>]/u.test(text)) return null;
  try {
    const document = parse(text);
    const root = document.documentElement;
    if (!root || root.tagName !== "svg" || readXmlParserIssue(document, "SVG")) {
      return { issues: ["SVG XML is malformed."] };
    }
    const omitted = new Set<string>();
    const nodes = drawingNodes(root, omitted);
    return { preview: { previewKind: "vector", vector: { format: "SVG", bounds: drawingBounds(root), nodes } },
      ...(omitted.size ? { issues: [`SVG preview omits ${[...omitted].join(", ")}.`] } : {}) };
  } catch { return { issues: ["SVG XML could not be parsed."] }; }
};
