 "use strict";

import { toHex32 } from "../../binary-utils.js";
import type { SevenZipParseResult, SevenZipStartHeader } from "../../analyzers/sevenz/index.js";
import { formatOffset, formatSize } from "./value-format.js";

export const renderSignatureLayout = (
  sevenZip: SevenZipParseResult,
  out: string[]
): void => {
  const header = sevenZip.startHeader as SevenZipStartHeader | undefined;
  if (!header) return;
  out.push(`<section>`);
  out.push(
    `<details><summary style="cursor:pointer;padding:.35rem .6rem;border:1px solid var(--border2);border-radius:8px;background:var(--chip-bg)"><b>Signature header map</b> (first 32 bytes)</summary>`
  );
  out.push(`<div style="margin-top:.5rem">`);
  out.push(
    `<div class="smallNote">The first 32 bytes of a 7z file are the signature header. It contains the magic signature, format version and the &quot;start header&quot; fields that locate the main header database.</div>`
  );
  out.push(
    `<table class="table"><thead><tr>` +
      `<th>Offset</th><th>Field</th><th>Value</th><th>Description</th>` +
    `</tr></thead><tbody>`
  );
  out.push(
    `<tr><td>0\u20135</td><td>Signature</td>` +
      `<td>37 7A BC AF 27 1C</td>` +
      `<td>6-byte magic &quot;7z\\xbc\\xaf'\\x1c&quot; that identifies the file as 7z.</td></tr>`
  );
  out.push(
    `<tr><td>6</td><td>VersionMajor</td>` +
      `<td>${header.versionMajor ?? "-"}</td>` +
      `<td>Major format version byte (currently 0).</td></tr>`
  );
  out.push(
    `<tr><td>7</td><td>VersionMinor</td>` +
      `<td>${header.versionMinor ?? "-"}</td>` +
      `<td>Minor format version byte (currently 4).</td></tr>`
  );
  out.push(
    `<tr><td>8\u201311</td><td>StartHeaderCRC</td>` +
      `<td>${toHex32(header.startHeaderCrc, 8)}</td>` +
      `<td>CRC32 over bytes 12\u201331 (NextHeaderOffset, NextHeaderSize, NextHeaderCRC).</td></tr>`
  );
  out.push(
    `<tr><td>12\u201319</td><td>NextHeaderOffset</td>` +
      `<td>${formatOffset(header.nextHeaderOffset)}</td>` +
      `<td>Relative offset (from byte 32) to the main header database.</td></tr>`
  );
  out.push(
    `<tr><td>20\u201327</td><td>NextHeaderSize</td>` +
      `<td>${formatSize(header.nextHeaderSize)}</td>` +
      `<td>Size in bytes of the encoded header database.</td></tr>`
  );
  out.push(
    `<tr><td>28\u201331</td><td>NextHeaderCRC</td>` +
      `<td>${toHex32(header.nextHeaderCrc ?? header.startHeaderCrc, 8)}</td>` +
      `<td>CRC32 of the header database after decoding.</td></tr>`
  );
  out.push(`</tbody></table>`);
  out.push(`</div></details>`);
  out.push(`</section>`);
};
