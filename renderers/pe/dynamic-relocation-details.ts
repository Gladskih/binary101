"use strict";

import { hex } from "../../binary-utils.js";
import type { PeDynamicRelocationEntry } from
  "../../analyzers/pe/dynamic-relocations/index.js";
import type { PeGuardRf } from "../../analyzers/pe/dynamic-relocations/guard-rf.js";
import type { PeArm64xFixup } from "../../analyzers/pe/dynamic-relocations/arm64x.js";

const ROW_LIMIT = 512;

const bytesHex = (bytes: number[]): string =>
  bytes.map(byte => byte.toString(16).padStart(2, "0")).join(" ") || "-";

const renderGuardRfMetadata = (guardRf: PeGuardRf): string => {
  if (guardRf.kind === "prologue") {
    return guardRf.prologueBytes === undefined ? "" :
      `<p>Prologue bytes: ${bytesHex(guardRf.prologueBytes)}</p>`;
  }
  if (guardRf.epilogueCount === undefined) return "";
  return `<p>Epilogue count: ${guardRf.epilogueCount}; ` +
    `epilogue byte count: ${guardRf.epilogueByteCount}; ` +
    `branch descriptor element size: ${guardRf.branchDescriptorElementSize}; ` +
    `branch descriptor count: ${guardRf.branchDescriptors?.length ?? 0}; ` +
    `branch descriptors: ${guardRf.branchDescriptors?.map(bytesHex).join(" | ") || "-"}; ` +
    `branch descriptor bitmap: ${bytesHex(guardRf.branchDescriptorBitmap ?? [])}</p>` +
    `<p>Bitmap bytes are shown raw; the Windows SDK header does not define their bits.</p>`;
};

const renderGuardRf = (guardRf: PeGuardRf): string => {
  const rows = guardRf.sites.slice(0, ROW_LIMIT).map(site =>
    `<tr><td>${hex(site.rva, 8)}</td><td class="num">${site.type}</td></tr>`).join("");
  const hidden = guardRf.sites.length - Math.min(guardRf.sites.length, ROW_LIMIT);
  return `<section class="loadConfigDynamicDetail"><h4>Guard RF ${guardRf.kind}</h4>` +
    renderGuardRfMetadata(guardRf) +
    `<p>Relocation sites: ${guardRf.sites.length}` +
    `${hidden ? `; showing first ${ROW_LIMIT}, ${hidden} hidden` : ""}</p>` +
    (rows ? `<div class="tableWrap"><table class="table"><thead><tr>` +
      `<th scope="col">RVA</th><th scope="col" class="num">Type</th>` +
      `</tr></thead><tbody>${rows}</tbody></table></div>` : "") + `</section>`;
};

const fixupValue = (fixup: PeArm64xFixup): string =>
  fixup.kind === "value" ? `0x${fixup.value.toString(16)}` :
    fixup.kind === "delta" ? String(fixup.delta) : "-";

const renderArm64x = (fixups: PeArm64xFixup[]): string => {
  // LLVM Arm64XRelocRef::getSize(): DELTA always modifies a 32-bit word.
  // https://github.com/llvm/llvm-project/blob/main/llvm/lib/Object/COFFObjectFile.cpp
  const rows = fixups.slice(0, ROW_LIMIT).map(fixup =>
    `<tr><td>${hex(fixup.rva, 8)}</td><td>${fixup.kind}</td>` +
    `<td class="num">${fixup.kind === "delta" ? 4 : fixup.size}</td>` +
    `<td class="num">${fixupValue(fixup)}</td></tr>`).join("");
  const hidden = fixups.length - Math.min(fixups.length, ROW_LIMIT);
  return `<section class="loadConfigDynamicDetail"><h4>ARM64X fixups</h4>` +
    `<p>Decoded records: ${fixups.length}` +
    `${hidden ? `; showing first ${ROW_LIMIT}, ${hidden} hidden` : ""}</p>` +
    (rows ? `<div class="tableWrap"><table class="table"><thead><tr>` +
      `<th scope="col">RVA</th><th scope="col">Type</th>` +
      `<th scope="col" class="num">Size</th><th scope="col" class="num">Value / delta</th>` +
      `</tr></thead><tbody>${rows}</tbody></table></div>` : "") + `</section>`;
};

export const renderDynamicRelocationDetails = (entries: PeDynamicRelocationEntry[]): string =>
  entries.map(entry => (entry.guardRf ? renderGuardRf(entry.guardRf) : "") +
    (entry.arm64xFixups ? renderArm64x(entry.arm64xFixups) : "")).join("");
