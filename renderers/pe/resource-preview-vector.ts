import type { ResourceVector } from "../../analyzers/pe/resources/preview/vector-types.js";
import { escapeHtmlText } from "../../html-utils.js";

export const renderVectorPreview = (vector: ResourceVector): string => {
  const markup: string[] = [];
  const stack = vector.nodes.slice().reverse().map(node => ({ node, closing: false }));
  while (stack.length) {
    const frame = stack.pop()!;
    if (frame.closing) { markup.push(`</${frame.node.tag}>`); continue; }
    markup.push(`<${frame.node.tag}${frame.node.attributes.map(attribute =>
      ` ${attribute.name}="${escapeHtmlText(attribute.value)}"`).join("")}>` +
      `${frame.node.text === null ? "" : escapeHtmlText(frame.node.text)}`);
    stack.push({ node: frame.node, closing: true });
    for (let index = frame.node.children.length - 1; index >= 0; index -= 1) {
      stack.push({ node: frame.node.children[index]!, closing: false });
    }
  }
  const box = vector.bounds;
  return `<figure class="peVector"><svg xmlns="http://www.w3.org/2000/svg" role="img" ` +
    `aria-label="${vector.format} resource drawing" viewBox="${box.x} ${box.y} ${box.width} ${box.height}" ` +
    `width="${box.width}" height="${box.height}">${markup.join("")}</svg>` +
    `<figcaption>${vector.format} drawing</figcaption></figure>` +
    (vector.records ? `<details><summary>${vector.records.length} metafile records</summary>` +
      `<table class="table"><thead><tr><th>Record type</th><th>Offset</th><th>Bytes</th></tr></thead><tbody>` +
      vector.records.map(record => `<tr><td>${record.type}</td><td>${record.offset}</td>` +
        `<td>${record.size}</td></tr>`).join("") + `</tbody></table></details>` : "");
};
