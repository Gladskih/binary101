"use strict";

import { renderDefinitionRow, escapeHtml } from "../../html-utils.js";
import { resolveEntryVirtualAddress } from "../../analyzers/macho/format.js";
import {
  dylibCommandKind,
  loadCommandDescription,
  loadCommandName,
  sectionAttributeFlagNames,
  sectionTypeName,
  segmentFlags,
  vmProtectionNames
} from "../../analyzers/macho/load-command-info.js";
import type { MachOEntryPoint, MachOImage, MachOSegment } from "../../analyzers/macho/types.js";
import {
  fileTypeLabel,
  headerCpuLabel,
  headerFlagLabels,
  magicLabel
} from "./header-semantics.js";
import {
  buildPlatformLabel,
  buildToolLabel,
  buildToolVersionText,
  packedVersionText,
  sourceVersionText,
  versionMinLabel
} from "./version-semantics.js";
import { renderCodeSignature } from "./codesign-view.js";
import { renderSymtab } from "./symbols-view.js";
import { formatByteSize, formatFileOffset, formatFileRange, formatHex, formatList } from "./value-format.js";

const entryFileOffset = (image: MachOImage, entryPoint: MachOEntryPoint): bigint =>
  BigInt(image.offset) + entryPoint.entryoff;

const entryVirtualAddress = (image: MachOImage, entryPoint: MachOEntryPoint): bigint | null =>
  resolveEntryVirtualAddress(image.segments, entryPoint.entryoff);

const renderSummary = (image: MachOImage): string => {
  const out: string[] = [];
  const kind = fileTypeLabel(image.header.filetype).toLowerCase();
  const cpu = headerCpuLabel(image.header);
  const segmentCount = image.segments.length;
  const symbolCount = image.symtab?.nsyms ?? 0;
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Big picture</h4>`);
  out.push(
    `<div class="smallNote">` +
      `${image.header.is64 ? "64-bit" : "32-bit"} Mach-O ${escapeHtml(kind)} for ${escapeHtml(cpu)}. ` +
      `${segmentCount} segment${segmentCount === 1 ? "" : "s"}, ` +
      `${image.loadCommands.length} load command${image.loadCommands.length === 1 ? "" : "s"}, ` +
      `${symbolCount} symbol${symbolCount === 1 ? "" : "s"}${image.codeSignature ? ", code-signed" : ""}.` +
    `</div>`
  );
  out.push(`</section>`);
  return out.join("");
};

const renderHeader = (image: MachOImage): string => {
  const out: string[] = [];
  const header = image.header;
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Mach-O header</h4>`);
  out.push(`<dl>`);
  out.push(renderDefinitionRow("Magic", escapeHtml(`${magicLabel(header.magic)} (${formatHex(header.magic)})`)));
  out.push(renderDefinitionRow("CPU", escapeHtml(headerCpuLabel(header))));
  out.push(renderDefinitionRow("File type", escapeHtml(fileTypeLabel(header.filetype))));
  out.push(renderDefinitionRow("Commands", escapeHtml(`${header.ncmds} (${header.sizeofcmds} bytes)`)));
  out.push(renderDefinitionRow("Flags", formatList(headerFlagLabels(header.flags))));
  if (header.reserved != null) out.push(renderDefinitionRow("Reserved", escapeHtml(formatHex(header.reserved))));
  out.push(`</dl>`);
  out.push(`</section>`);
  return out.join("");
};

const renderVersions = (image: MachOImage): string => {
  if (!image.buildVersions.length && !image.minVersions.length && !image.sourceVersion) return "";
  const out: string[] = [];
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Build metadata</h4>`);
  if (image.buildVersions.length) {
    out.push(`<ul>`);
    for (const build of image.buildVersions) {
      const tools = build.tools.length
        ? `; tools: ${build.tools
            .map(tool => `${buildToolLabel(tool.tool)} ${buildToolVersionText(tool.version)}`)
            .join(", ")}`
        : "";
      out.push(
        `<li>${escapeHtml(buildPlatformLabel(build.platform))} ` +
          `(min ${escapeHtml(packedVersionText(build.minos))}, sdk ${escapeHtml(packedVersionText(build.sdk))}${escapeHtml(tools)})</li>`
      );
    }
    out.push(`</ul>`);
  }
  if (image.minVersions.length) {
    out.push(`<ul>`);
    for (const version of image.minVersions) {
      out.push(
        `<li>${escapeHtml(versionMinLabel(version.command))} min ${escapeHtml(packedVersionText(version.version))}, ` +
          `sdk ${escapeHtml(packedVersionText(version.sdk))}</li>`
      );
    }
    out.push(`</ul>`);
  }
  if (image.sourceVersion) {
    out.push(`<div class="smallNote">Source version ${escapeHtml(sourceVersionText(image.sourceVersion.value))}</div>`);
  }
  out.push(`</section>`);
  return out.join("");
};

const renderEntryPoint = (image: MachOImage): string => {
  if (!image.entryPoint && !image.uuid && !image.stringCommands.length) return "";
  const out: string[] = [];
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Identity and startup</h4>`);
  out.push(`<dl>`);
  if (image.uuid) out.push(renderDefinitionRow("UUID", `<span class="mono">${escapeHtml(image.uuid)}</span>`));
  if (image.entryPoint) {
    const fileOffset = entryFileOffset(image, image.entryPoint);
    const virtualAddress = entryVirtualAddress(image, image.entryPoint);
    out.push(renderDefinitionRow("Entry offset", `<span class="mono">${escapeHtml(formatHex(image.entryPoint.entryoff))}</span>`));
    out.push(renderDefinitionRow("Entry file offset", `<span class="mono">${escapeHtml(formatHex(fileOffset))}</span>`));
    out.push(
      renderDefinitionRow(
        "Entry virtual address",
        virtualAddress != null
          ? `<span class="mono">${escapeHtml(formatHex(virtualAddress))}</span>`
          : "<span class=\"muted\">Not mapped by parsed segments</span>"
      )
    );
    if (image.entryPoint.stacksize !== 0n) {
      out.push(renderDefinitionRow("Initial stack", escapeHtml(formatByteSize(image.entryPoint.stacksize))));
    }
  }
  for (const stringCommand of image.stringCommands) {
    out.push(renderDefinitionRow(loadCommandName(stringCommand.command), `<span class="mono">${escapeHtml(stringCommand.value || "-")}</span>`));
  }
  out.push(`</dl>`);
  out.push(`</section>`);
  return out.join("");
};

const renderLoadCommands = (image: MachOImage): string => {
  if (!image.loadCommands.length) return "";
  const out: string[] = [];
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Load commands</h4>`);
  out.push(
    `<details><summary style="cursor:pointer;padding:.25rem .5rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg)">` +
      `Show commands (${image.loadCommands.length})</summary>`
  );
  out.push(`<div class="tableWrap"><table class="table"><thead><tr><th>#</th><th>Command</th><th>Offset</th><th>Size</th><th>Meaning</th></tr></thead><tbody>`);
  for (const command of image.loadCommands) {
    out.push(
      `<tr><td>${command.index}</td><td>${escapeHtml(loadCommandName(command.cmd))}</td>` +
        `<td><span class="mono">${escapeHtml(formatHex(command.offset))}</span></td>` +
        `<td>${escapeHtml(String(command.cmdsize))}</td>` +
        `<td>${escapeHtml(loadCommandDescription(command.cmd) || "-")}</td></tr>`
    );
  }
  out.push(`</tbody></table></div></details></section>`);
  return out.join("");
};

const renderLinkedImages = (image: MachOImage): string => {
  if (!image.dylibs.length && !image.rpaths.length && !image.idDylib) return "";
  const out: string[] = [];
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Linking</h4>`);
  if (image.idDylib) {
    out.push(`<div class="smallNote">Install name: <span class="mono">${escapeHtml(image.idDylib.name)}</span></div>`);
  }
  if (image.dylibs.length) {
    out.push(`<ul>`);
    for (const dylib of image.dylibs) {
      out.push(
        `<li>${escapeHtml(dylibCommandKind(dylib.command))}: <span class="mono">${escapeHtml(dylib.name || "-")}</span> ` +
          `(compat ${escapeHtml(packedVersionText(dylib.compatibilityVersion))}, ` +
          `current ${escapeHtml(packedVersionText(dylib.currentVersion))})</li>`
      );
    }
    out.push(`</ul>`);
  }
  if (image.rpaths.length) {
    out.push(`<div class="smallNote">RPATHs: ${image.rpaths.map(item => `<span class="mono">${escapeHtml(item.path)}</span>`).join(", ")}</div>`);
  }
  out.push(`</section>`);
  return out.join("");
};

const renderSegments = (image: MachOImage, segments: MachOSegment[]): string => {
  if (!segments.length) return "";
  const out: string[] = [];
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Segments and sections</h4>`);
  out.push(
    `<details><summary style="cursor:pointer;padding:.25rem .5rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg)">` +
      `Show layout (${segments.length} segments)</summary>`
  );
  out.push(`<div class="tableWrap"><table class="table"><thead><tr><th>Segment</th><th>VM</th><th>File</th><th>Protections</th><th>Sections</th><th>Flags</th></tr></thead><tbody>`);
  for (const segment of segments) {
    const initProtection = vmProtectionNames(segment.initprot).join("/") || "-";
    const maxProtection = vmProtectionNames(segment.maxprot).join("/") || "-";
    out.push(
      `<tr><td>${escapeHtml(segment.name || "<unnamed>")}</td>` +
        `<td><span class="mono">${escapeHtml(formatHex(segment.vmaddr))}</span> / ${escapeHtml(formatByteSize(segment.vmsize))}</td>` +
        `<td><span class="mono">${escapeHtml(formatFileOffset(image.offset, segment.fileoff))}</span> / ${escapeHtml(formatByteSize(segment.filesize))}</td>` +
        `<td>init: ${escapeHtml(initProtection)}<br>max: ${escapeHtml(maxProtection)}</td>` +
        `<td>${segment.sections.length}</td>` +
        `<td>${formatList(segmentFlags(segment.flags))}</td></tr>`
    );
  }
  out.push(`</tbody></table></div>`);
  const sections = segments.flatMap(segment => segment.sections);
  if (sections.length) {
    out.push(`<div class="tableWrap"><table class="table"><thead><tr><th>#</th><th>Section</th><th>Segment</th><th>Address</th><th>Size</th><th>Offset</th><th>Type</th><th>Attributes</th></tr></thead><tbody>`);
    for (const section of sections) {
      out.push(
        `<tr><td>${section.index}</td><td>${escapeHtml(section.sectionName)}</td><td>${escapeHtml(section.segmentName)}</td>` +
          `<td><span class="mono">${escapeHtml(formatHex(section.addr))}</span></td>` +
          `<td>${escapeHtml(formatByteSize(section.size))}</td>` +
          `<td><span class="mono">${escapeHtml(formatFileOffset(image.offset, section.offset))}</span></td>` +
          `<td>${escapeHtml(sectionTypeName(section.flags))}</td>` +
          `<td>${formatList(sectionAttributeFlagNames(section.flags))}</td></tr>`
      );
    }
    out.push(`</tbody></table></div>`);
  }
  out.push(`</details></section>`);
  return out.join("");
};

const renderImage = (image: MachOImage): string => {
  const out: string[] = [];
  out.push(renderSummary(image));
  out.push(renderHeader(image));
  out.push(renderVersions(image));
  out.push(renderEntryPoint(image));
  out.push(renderLinkedImages(image));
  out.push(renderLoadCommands(image));
  out.push(renderSegments(image, image.segments));
  out.push(renderSymtab(image));
  if (image.codeSignature) out.push(renderCodeSignature(image.codeSignature, image.offset));
  if (
    image.dyldInfo ||
    image.linkeditData.length ||
    image.encryptionInfos.length ||
    image.fileSetEntries.length
  ) {
    out.push(`<section>`);
    out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Extra loader metadata</h4>`);
    out.push(`<dl>`);
    if (image.dyldInfo) {
      out.push(renderDefinitionRow("Dyld info", escapeHtml(`rebase ${image.dyldInfo.rebaseSize} B, bind ${image.dyldInfo.bindSize} B, export ${image.dyldInfo.exportSize} B`)));
    }
    for (const item of image.linkeditData) {
      out.push(
        renderDefinitionRow(
          loadCommandName(item.command),
          escapeHtml(formatFileRange(image.offset, item.dataoff, item.datasize))
        )
      );
    }
    for (const info of image.encryptionInfos) {
      out.push(
        renderDefinitionRow(
          loadCommandName(info.command),
          escapeHtml(`${formatFileRange(image.offset, info.cryptoff, info.cryptsize)}, cryptid ${info.cryptid}`)
        )
      );
    }
    for (const entry of image.fileSetEntries) {
      out.push(
        renderDefinitionRow(
          "Fileset entry",
          `<span class="mono">${escapeHtml(entry.entryId || "-")}</span> @ ${escapeHtml(formatFileOffset(image.offset, entry.fileoff))}`
        )
      );
    }
    out.push(`</dl></section>`);
  }
  if (image.issues.length) {
    out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Notices</h4><ul>`);
    for (const issue of image.issues) out.push(`<li>${escapeHtml(issue)}</li>`);
    out.push(`</ul></section>`);
  }
  return out.join("");
};

export { renderImage };
