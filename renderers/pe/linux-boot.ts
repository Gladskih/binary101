"use strict";

import { escapeHtml, renderDefinitionRow, renderFlagChips } from "../../html-utils.js";
import { hex, hex64, humanSize } from "../../binary-utils.js";
import type { PeWindowsParseResult } from "../../analyzers/pe/index.js";
import { formatLinuxBootProtocolVersion } from "../../analyzers/pe/linux-boot.js";
import { renderDownloadButton } from "../download-button.js";
import { renderPeDiagnostics } from "./diagnostics.js";
import { renderPeSectionEnd, renderPeSectionStart } from "./collapsible-section.js";

type PeLinuxBoot = NonNullable<PeWindowsParseResult["linuxBoot"]>;
type PeLinuxPayload = NonNullable<PeLinuxBoot["payload"]>;

// Linux/x86 Boot Protocol xloadflags bits:
// https://docs.kernel.org/arch/x86/boot.html#details-of-header-fields
const XLOAD_FLAGS: Array<[number, string, string]> = [
  [0x01, "KERNEL_64", "Legacy 64-bit entry point at 0x200"],
  [0x02, "ABOVE_4G", "Kernel, boot params, command line, and ramdisk can be above 4G"],
  [0x04, "EFI_32", "32-bit EFI handover entry point is supported"],
  [0x08, "EFI_64", "64-bit EFI handover entry point is supported"],
  [0x10, "EFI_KEXEC", "kexec EFI boot with EFI runtime support is supported"]
];

const LOAD_FLAGS: Array<[number, string, string]> = [
  [0x01, "LOAD_HIGH", "bzImage kernel loaded in high memory"],
  [0x80, "CAN_USE_HEAP", "Heap fields are usable by the boot loader"]
];

const renderPayloadDownloadButton = (payload: PeLinuxPayload): string =>
  renderDownloadButton("Download compressed Linux payload", [
    ["data-pe-linux-payload-download"],
    ["data-linux-payload-start", payload.fileOffset],
    ["data-linux-payload-end", payload.endOffset]
  ]);

const renderPayload = (payload: PeLinuxPayload, out: string[]): void => {
  out.push(
    `<div class="peOverlayRangeHeader"><div><b>Compressed payload</b>` +
    `<div class="smallNote">${hex(payload.fileOffset, 8)}-${hex(payload.endOffset, 8)}; ` +
    `${humanSize(payload.length)}</div></div>${renderPayloadDownloadButton(payload)}</div>`
  );
  out.push(`<dl>`);
  out.push(renderDefinitionRow("payload_offset", hex(payload.offset, 8), "Offset from protected-mode code start."));
  out.push(renderDefinitionRow("payload_length", humanSize(payload.length), "Compressed payload byte length."));
  out.push(renderDefinitionRow("Detected stream", escapeHtml(payload.format)));
  out.push(renderDefinitionRow("Magic bytes", escapeHtml(payload.magicHex ?? "-")));
  if (payload.gzip) {
    out.push(renderDefinitionRow(
      "gzip analyzer",
      `${payload.gzip.issues.length} issue(s)`,
      "Parsed by the existing gzip analyzer against the Linux payload byte range."
    ));
    out.push(renderDefinitionRow(
      "gzip compressed data",
      payload.gzip.stream.compressedOffset != null && payload.gzip.stream.compressedSize != null
        ? `+${hex(payload.gzip.stream.compressedOffset, 4)}; ${humanSize(payload.gzip.stream.compressedSize)}`
        : "-"
    ));
    out.push(renderDefinitionRow(
      "gzip trailer",
      payload.gzip.stream.trailerOffset != null ? `+${hex(payload.gzip.stream.trailerOffset, 4)}` : "-"
    ));
  }
  out.push(`</dl>`);
  if (payload.gzip?.issues.length) out.push(renderPeDiagnostics("gzip payload warnings", payload.gzip.issues));
};

const renderKernelInfo = (linux: PeLinuxBoot, out: string[]): void => {
  if (!linux.kernelInfo) return;
  const info = linux.kernelInfo;
  out.push(`<details style="margin-top:.35rem" open><summary>kernel_info</summary><dl>`);
  out.push(renderDefinitionRow("File offset", hex(info.fileOffset, 8)));
  out.push(renderDefinitionRow("Header", escapeHtml(info.header || "-")));
  out.push(renderDefinitionRow("Size", humanSize(info.size)));
  out.push(renderDefinitionRow("Total size", humanSize(info.totalSize)));
  out.push(renderDefinitionRow("setup_type_max", hex(info.setupTypeMax, 8)));
  out.push(`</dl></details>`);
  if (info.warnings?.length) out.push(renderPeDiagnostics("kernel_info warnings", info.warnings));
};

const renderLinuxBootFields = (linux: PeLinuxBoot, out: string[]): void => {
  out.push(`<dl>`);
  out.push(renderDefinitionRow("Protocol", formatLinuxBootProtocolVersion(linux.protocolVersion)));
  out.push(renderDefinitionRow("setup_sects", `${linux.setupSectors} (${linux.setupSectorsRaw} raw)`));
  out.push(renderDefinitionRow("boot_flag", hex(linux.bootFlag, 4)));
  out.push(renderDefinitionRow("kernel_version", escapeHtml(linux.kernelVersion ?? "-")));
  out.push(renderDefinitionRow("kernel_version offset", hex(linux.kernelVersionOffset, 4)));
  out.push(renderDefinitionRow("loadflags", renderFlagChips(linux.loadFlags, LOAD_FLAGS)));
  if (linux.xloadFlags != null) {
    out.push(renderDefinitionRow("xloadflags", renderFlagChips(linux.xloadFlags, XLOAD_FLAGS)));
  }
  if (linux.kernelAlignment != null) out.push(renderDefinitionRow("kernel_alignment", humanSize(linux.kernelAlignment)));
  if (linux.relocatableKernel != null) {
    out.push(renderDefinitionRow("relocatable_kernel", linux.relocatableKernel ? "Yes" : "No"));
  }
  if (linux.cmdlineSize != null) out.push(renderDefinitionRow("cmdline_size", `${linux.cmdlineSize} characters`));
  if (linux.preferredAddress != null) out.push(renderDefinitionRow("pref_address", hex64(linux.preferredAddress)));
  if (linux.initSize != null) out.push(renderDefinitionRow("init_size", humanSize(linux.initSize)));
  if (linux.handoverOffset != null) out.push(renderDefinitionRow("handover_offset", hex(linux.handoverOffset, 8)));
  if (linux.kernelInfoOffset != null) out.push(renderDefinitionRow("kernel_info_offset", hex(linux.kernelInfoOffset, 8)));
  out.push(`</dl>`);
};

export const getLinuxBootSummary = (linux: PeLinuxBoot): string =>
  `protocol ${formatLinuxBootProtocolVersion(linux.protocolVersion)}` +
  (linux.payload ? `, ${linux.payload.format} payload` : "");

export const renderLinuxBoot = (pe: PeWindowsParseResult, out: string[]): void => {
  const linux = pe.linuxBoot;
  if (!linux) return;
  out.push(renderPeSectionStart("Linux boot protocol", getLinuxBootSummary(linux)));
  if (linux.warnings?.length) out.push(renderPeDiagnostics("Linux boot warnings", linux.warnings));
  renderLinuxBootFields(linux, out);
  if (linux.payload) renderPayload(linux.payload, out);
  renderKernelInfo(linux, out);
  out.push(renderPeSectionEnd());
};
