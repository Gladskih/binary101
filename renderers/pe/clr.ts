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

const TOKEN_TABLE_NAMES: Record<number, string> = {
  0x02: "TypeDef",
  0x04: "Field",
  0x06: "MethodDef",
  0x08: "Param",
  0x0a: "MemberRef",
  0x20: "Assembly",
  0x23: "AssemblyRef",
  0x26: "File",
  0x27: "ExportedType",
  0x2b: "MethodSpec"
};

const VTABLE_FIXUP_TYPE_FLAGS: Array<[number, string]> = [
  [0x0001, "32BIT"],
  [0x0002, "64BIT"],
  [0x0004, "FROM_UNMANAGED"],
  [0x0010, "CALL_MOST_DERIVED"]
];

const KNOWN_METADATA_STREAM_TYPES: Record<string, string> = {
  "#~": "Compressed metadata tables",
  "#-": "Uncompressed metadata tables",
  "#Strings": "String heap",
  "#US": "User string heap",
  "#GUID": "GUID heap",
  "#Blob": "Blob heap"
};

const formatClrDirectory = (rva: number, size: number): string =>
  rva || size ? `RVA ${hex(rva, 8)} Size ${humanSize(size)}` : "-";

const decodeEntryPointToken = (token: number): string => {
  const tableId = (token >>> 24) & 0xff;
  const rowId = token & 0x00ffffff;
  const tableName = TOKEN_TABLE_NAMES[tableId] || "UnknownTable";
  return `${hex(token, 8)} (${tableName}, RID ${rowId})`;
};

const formatVTableFixupType = (value: number): string => {
  const names = VTABLE_FIXUP_TYPE_FLAGS.filter(([flag]) => (value & flag) !== 0).map(([, name]) => name);
  const knownMask = VTABLE_FIXUP_TYPE_FLAGS.reduce((mask, [flag]) => mask | flag, 0);
  if ((value & ~knownMask) !== 0) {
    names.push("UNKNOWN_BITS");
  }
  return names.length ? `${hex(value, 4)} (${names.join(" | ")})` : hex(value, 4);
};

const describeMetadataStreamType = (name: string): string =>
  KNOWN_METADATA_STREAM_TYPES[name] || "Unknown stream type";

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
      "VTable fixups table used for unmanaged interop stubs."
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
          `<td>${entry.Count}</td><td>${safe(formatVTableFixupType(entry.Type))}</td></tr>`
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
  out.push(`<details style="margin-top:.35rem" open><summary>Metadata root</summary><dl>`);
  if (meta.version) {
    out.push(dd("VersionString", safe(meta.version), "Metadata version string from the metadata root."));
  }
  if (meta.verMajor != null && meta.verMinor != null) {
    out.push(
      dd(
        "Version",
        `${meta.verMajor}.${meta.verMinor}`,
        "Metadata root format version fields (major/minor)."
      )
    );
  }
  if (meta.signature != null) {
    out.push(dd("Signature", hex(meta.signature, 8), "Metadata root signature, expected BSJB."));
  }
  if (meta.flags != null) {
    out.push(dd("Flags", hex(meta.flags, 4), "Metadata root flags field."));
  }
  if (meta.reserved != null) {
    out.push(dd("Reserved", hex(meta.reserved, 8), "Reserved metadata root value (usually 0)."));
  }
  if (meta.streamCount != null) {
    out.push(
      dd(
        "StreamCount",
        `${meta.streamCount} declared, ${meta.streams.length} parsed`,
        "Declared stream header count versus successfully parsed stream entries."
      )
    );
  }
  out.push(`</dl></details>`);
  if (!meta.streams?.length) return;
  out.push(
    `<details style="margin-top:.35rem"><summary>` +
      `Metadata streams (${meta.streams.length})` +
      `</summary>`
  );
  out.push(
    `<table class="table" style="margin-top:.35rem">` +
      `<thead><tr><th>#</th><th>Name</th><th>Type</th><th>Offset</th><th>End</th><th>Size</th></tr></thead>` +
      `<tbody>`
  );
  meta.streams.forEach((stream, index) => {
    const streamEnd = stream.offset + stream.size;
    out.push(
      `<tr><td>${index + 1}</td><td>${safe(stream.name)}</td><td>${safe(describeMetadataStreamType(stream.name))}</td>` +
        `<td>${hex(stream.offset, 8)}</td><td>${hex(streamEnd, 8)}</td><td>${humanSize(stream.size)}</td></tr>`
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
        safe(decodeEntryPointToken(clrHeader.EntryPointToken)),
        "Managed method token (table id + RID) used as the startup entry point."
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
