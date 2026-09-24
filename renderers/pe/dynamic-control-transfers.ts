"use strict";

import { hex } from "../../binary-utils.js";
import type { PeDynamicRelocationEntry } from
  "../../analyzers/pe/dynamic-relocations/index.js";
import type { PeControlTransferRecord } from
  "../../analyzers/pe/dynamic-relocations/control-transfers.js";
import { getDynamicRelocationSymbolName } from "./dynamic-relocation-symbols.js";

const RENDER_LIMIT = 512;

const describeRecord = (record: PeControlTransferRecord): [string, string] => {
  switch (record.kind) {
    case "import":
      return [record.indirectCall ? "call" : "branch", `IAT index ${record.iatIndex}`];
    case "arm64Import":
      return [record.indirectCall ? "BLR" : "BR", [
        `register ${record.registerIndex}`, record.delayImport ? "delay import" : "static import",
        record.iatIndex == null ? "IAT index unavailable" : `IAT index ${record.iatIndex}`
      ].join(", ")];
    case "indirect":
      return [record.indirectCall ? "call" : "branch", [
        ...(record.rexWPrefix ? ["REX.W"] : []),
        ...(record.cfgCheck ? ["CFG check"] : [])
      ].join(", ") || "-"];
    case "switch":
      return ["branch", `register ${record.registerNumber}`];
  }
};

export const renderDynamicControlTransfers = (entries: PeDynamicRelocationEntry[]): string => {
  const count = entries.reduce((sum, entry) => sum + (entry.controlTransfers?.length ?? 0), 0);
  if (!count) return "";
  const rows: string[] = [];
  for (const entry of entries) {
    for (const record of entry.controlTransfers ?? []) {
      if (rows.length >= RENDER_LIMIT) break;
      const [transfer, detail] = describeRecord(record);
      rows.push(`<tr><td>${getDynamicRelocationSymbolName(entry.symbol)}</td>` +
        `<td>${hex(record.rva, 8)}</td><td>${transfer}</td><td>${detail}</td></tr>`);
    }
    if (rows.length >= RENDER_LIMIT) break;
  }
  const hidden = count - rows.length;
  return `<div class="smallNote">Control-transfer fixups (${count})</div>` +
    `<div class="tableWrap"><table class="table"><thead><tr>` +
    `<th>Symbol</th><th>Instruction RVA</th><th>Transfer</th>` +
    `<th>Details</th></tr></thead><tbody>${rows.join("")}</tbody></table></div>` +
    `${hidden ? `<div class="smallNote">${hidden} more fixups hidden</div>` : ""}`;
};
