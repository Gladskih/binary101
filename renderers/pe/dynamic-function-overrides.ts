"use strict";

import { hex } from "../../binary-utils.js";
import type { PeFunctionOverride } from "../../analyzers/pe/dynamic-relocations/function-override.js";

const RENDER_LIMIT = 512;

// Windows SDK winnt.h: IMAGE_FUNCTION_OVERRIDE_* relocation types.
// https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/winnt.h
const relocationTypeName = (type: number): string => {
  if (type === 0) return "INVALID";
  if (type === 1) return "X64_REL32";
  if (type === 2) return "ARM64_BRANCH26";
  if (type === 3) return "ARM64_THUNK";
  return `Unknown (${type})`;
};

const renderRelocations = (fixup: PeFunctionOverride): string => {
  const count = fixup.functions.reduce((total, record) => total + record.baseRelocations.reduce(
    (blockTotal, block) => blockTotal + block.entries.length, 0
  ), 0);
  if (!count) return "";
  const visible: string[] = [];
  for (const record of fixup.functions) {
    for (const block of record.baseRelocations) {
      for (const entry of block.entries) {
        if (visible.length >= RENDER_LIMIT) break;
        const rva = block.pageRva + entry.offset;
        visible.push(`<tr><td>${hex(record.originalRva, 8)}</td>` +
          `<td>${hex(block.pageRva, 8)}</td><td>${relocationTypeName(entry.type)}</td>` +
          `<td>${hex(entry.offset, 3)}</td>` +
          `<td>${rva <= 0xffff_ffff ? hex(rva, 8) : "Out of range"}</td></tr>`);
      }
    }
  }
  return `<details><summary>Relocations (${count})</summary>` +
    `<div class="tableWrap"><table class="table"><thead><tr><th>Original RVA</th>` +
    `<th>Page RVA</th><th>Type</th><th>Offset</th><th>RVA</th></tr></thead>` +
    `<tbody>${visible.join("")}</tbody></table></div>` +
    `${count > RENDER_LIMIT
      ? `<div class="smallNote">${count - RENDER_LIMIT} more relocations hidden</div>` : ""}` +
    `</details>`;
};

const renderBddNodes = (fixup: PeFunctionOverride): string => {
  const count = fixup.bddInfos.reduce((total, info) => total + info.nodes.length, 0);
  if (!count) return "";
  const rows: string[] = [];
  for (const info of fixup.bddInfos) {
    for (const [index, node] of info.nodes.entries()) {
      if (rows.length >= RENDER_LIMIT) break;
      rows.push(`<tr><td>${hex(info.offset, 8)}</td><td class="num">${index}</td>` +
        `<td class="num">${node.left}</td><td class="num">${node.right}</td>` +
        `<td>${hex(node.value, 8)}</td></tr>`);
    }
    if (rows.length >= RENDER_LIMIT) break;
  }
  const hidden = count - rows.length;
  return `<details><summary>BDD nodes (${count})</summary>` +
    `<div class="tableWrap"><table class="table"><thead><tr><th>BDD offset</th>` +
    `<th>#</th><th>Left</th><th>Right</th><th>Value</th></tr></thead>` +
    `<tbody>${rows.slice(0, RENDER_LIMIT).join("")}</tbody></table></div>` +
    `${hidden ? `<div class="smallNote">${hidden} more nodes hidden</div>` : ""}</details>`;
};

export const renderDynamicFunctionOverrides = (fixup: PeFunctionOverride): string => {
  const bddByOffset = new Map(fixup.bddInfos.map(info => [info.offset, info]));
  const rows = fixup.functions.slice(0, RENDER_LIMIT).map(record => {
    const bdd = bddByOffset.get(record.bddOffset);
    const relocations = record.baseRelocations.reduce(
      (count, block) => count + block.entries.length, 0
    );
    return `<tr><td>${hex(record.originalRva, 8)}</td>` +
      `<td>${record.overridingRvas.map(rva => hex(rva, 8)).join(", ") || "-"}</td>` +
      `<td>${bdd ? `BDD +${hex(record.bddOffset, 8)}, v${bdd.version}, ${bdd.nodes.length} ` +
        `node${bdd.nodes.length === 1 ? "" : "s"}` : "-"}</td>` +
      `<td class="num">${relocations}</td></tr>`;
  });
  const hidden = Math.max(0, fixup.functions.length - RENDER_LIMIT);
  return `<div class="smallNote">Function override (${fixup.functions.length} functions)</div>` +
    `<div class="tableWrap"><table class="table"><thead><tr>` +
    `<th>Original RVA</th><th>Overriding RVAs</th><th>BDD</th>` +
    `<th>Relocations</th></tr></thead><tbody>${rows.join("")}</tbody></table></div>` +
    `${hidden ? `<div class="smallNote">${hidden} more functions hidden</div>` : ""}` +
    renderRelocations(fixup) + renderBddNodes(fixup);
};
