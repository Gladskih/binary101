"use strict";

import { humanSize, hex } from "../../binary-utils.js";
import { dd, rowFlags, safe } from "../../html-utils.js";
import type { PeParseResult } from "../../analyzers/pe/index.js";

const COMIMAGE_FLAGS_NATIVE_ENTRYPOINT = 0x00000010;

const CLR_IMAGE_FLAGS: Array<[number, string, string?]> = [
  [0x00000001, "ILONLY", "Contains only IL code (no native entrypoint)."],
  [0x00000002, "32BITREQUIRED", "Requires a 32-bit process."],
  [0x00000004, "ILLIBRARY", "Image is an IL library."],
  [0x00000008, "STRONGNAMESIGNED", "Strong-name signed."],
  [
    COMIMAGE_FLAGS_NATIVE_ENTRYPOINT,
    "NATIVE_ENTRYPOINT",
    "EntryPointToken is an RVA (native entrypoint)."
  ],
  [0x00010000, "TRACKDEBUGDATA", "Track debug data."],
  [0x00020000, "32BITPREFERRED", "Prefer 32-bit (where supported)."]
];

const formatClrDirectory = (rva: number, size: number): string =>
  rva || size ? `RVA ${hex(rva, 8)} Size ${humanSize(size)}` : "-";

const renderClrSubdirectories = (pe: PeParseResult, out: string[]): void => {
  const clrHeader = pe.clr;
  if (!clrHeader) return;
  const subdirectories: Array<[string, number, number, string]> = [
    [
      "Resources",
      clrHeader.ResourcesRVA,
      clrHeader.ResourcesSize,
      "Managed resources directory (not the PE .rsrc tree)."
    ],
    [
      "StrongNameSignature",
      clrHeader.StrongNameSignatureRVA,
      clrHeader.StrongNameSignatureSize,
      "Strong-name signature blob."
    ],
    [
      "CodeManagerTable",
      clrHeader.CodeManagerTableRVA,
      clrHeader.CodeManagerTableSize,
      "Code manager table (rare)."
    ],
    [
      "VTableFixups",
      clrHeader.VTableFixupsRVA,
      clrHeader.VTableFixupsSize,
      "VTable fixups table (interop)."
    ],
    [
      "ExportAddressTableJumps",
      clrHeader.ExportAddressTableJumpsRVA,
      clrHeader.ExportAddressTableJumpsSize,
      "Export address table jumps (rare)."
    ],
    [
      "ManagedNativeHeader",
      clrHeader.ManagedNativeHeaderRVA,
      clrHeader.ManagedNativeHeaderSize,
      "Managed native header (mixed-mode)."
    ]
  ];
  if (
    !subdirectories.some(([, rva, size]) => rva || size) &&
    !clrHeader.vtableFixups?.length
  ) {
    return;
  }
  out.push(
    `<details style="margin-top:.35rem"><summary>CLR subdirectories</summary>` +
      `<dl>`
  );
  subdirectories.forEach(([name, rva, size, tip]) => {
    out.push(dd(name, formatClrDirectory(rva, size), tip));
  });
  out.push(`</dl>`);
  if (clrHeader.vtableFixups?.length) {
    out.push(
      `<details style="margin-top:.35rem"><summary>` +
        `VTableFixups entries (${clrHeader.vtableFixups.length})` +
        `</summary>`
    );
    out.push(
      `<table class="table" style="margin-top:.35rem">` +
        `<thead><tr><th>#</th><th>RVA</th><th>Count</th><th>Type</th></tr></thead>` +
        `<tbody>`
    );
    clrHeader.vtableFixups.forEach((entry, index) => {
      out.push(
        `<tr><td>${index + 1}</td><td>${hex(entry.RVA, 8)}</td>` +
          `<td>${entry.Count}</td><td>${hex(entry.Type, 4)}</td></tr>`
      );
    });
    out.push(`</tbody></table></details>`);
  }
  out.push(`</details>`);
};

const renderClrMetadata = (pe: PeParseResult, out: string[]): void => {
  const clrHeader = pe.clr;
  if (!clrHeader?.meta) return;
  const meta = clrHeader.meta;
  if (meta.version) {
    out.push(`<div class="smallNote">Metadata version: ${safe(meta.version)}</div>`);
  }
  if (!meta.streams?.length) return;
  out.push(
    `<details style="margin-top:.35rem"><summary>` +
      `Metadata streams (${meta.streams.length})` +
      `</summary>`
  );
  out.push(
    `<table class="table" style="margin-top:.35rem">` +
      `<thead><tr><th>#</th><th>Name</th><th>Offset</th><th>Size</th></tr></thead>` +
      `<tbody>`
  );
  meta.streams.forEach((stream, index) => {
    out.push(
      `<tr><td>${index + 1}</td><td>${safe(stream.name)}</td>` +
        `<td>${hex(stream.offset, 8)}</td><td>${humanSize(stream.size)}</td></tr>`
    );
  });
  out.push(`</tbody></table></details>`);
};

export function renderClr(pe: PeParseResult, out: string[]): void {
  if (!pe.clr) return;
  const clrHeader = pe.clr;
  out.push(
    `<section>` +
      `<h4 style="margin:0 0 .5rem 0;font-size:.9rem">CLR (.NET) header</h4>` +
      `<dl>`
  );
  out.push(dd("Size", String(clrHeader.cb), "Size of IMAGE_COR20_HEADER in bytes."));
  out.push(
    dd(
      "RuntimeVersion",
      `${clrHeader.MajorRuntimeVersion}.${clrHeader.MinorRuntimeVersion}`,
      "CLR runtime version required by this assembly."
    )
  );
  out.push(
    dd(
      "MetaData",
      formatClrDirectory(clrHeader.MetaDataRVA, clrHeader.MetaDataSize),
      "Location and size of CLR metadata streams (tables/heap)."
    )
  );
  out.push(
    dd(
      "Flags",
      `<div class="mono">${safe(hex(clrHeader.Flags, 8))}</div>` +
        rowFlags(clrHeader.Flags, CLR_IMAGE_FLAGS),
      "CLR image flags (COMIMAGE_FLAGS)."
    )
  );
  if ((clrHeader.Flags & COMIMAGE_FLAGS_NATIVE_ENTRYPOINT) !== 0) {
    out.push(
      dd(
        "EntryPointRVA",
        hex(clrHeader.EntryPointToken, 8),
        "Native entry point RVA (COMIMAGE_FLAGS_NATIVE_ENTRYPOINT)."
      )
    );
  } else {
    out.push(
      dd(
        "EntryPointToken",
        hex(clrHeader.EntryPointToken, 8),
        "Managed entry point method token (MethodDef/...)."
      )
    );
  }
  out.push(`</dl>`);
  renderClrSubdirectories(pe, out);
  if (clrHeader.issues?.length) {
    out.push(`<ul class="smallNote" style="color:var(--warn-fg)">`);
    clrHeader.issues.forEach(issue => out.push(`<li>${safe(issue)}</li>`));
    out.push(`</ul>`);
  }
  renderClrMetadata(pe, out);
  out.push(`</section>`);
}

