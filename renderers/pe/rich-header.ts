"use strict";

import { hex } from "../../binary-utils.js";
import { dd, safe } from "../../html-utils.js";
import type { PeParseResult } from "../../analyzers/pe/index.js";
import type { PeRichHeaderEntry } from "../../analyzers/pe/types.js";

const formatCompId = (entry: PeRichHeaderEntry): number =>
  (((entry.productId & 0xffff) << 16) | (entry.buildNumber & 0xffff)) >>> 0;

export function renderRichHeader(pe: PeParseResult, out: string[]): void {
  const rich = pe.dos.rich;
  if (!rich) return;

  out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Rich header</h4>`);
  out.push(
    `<div class="smallNote">A build fingerprint hidden in the DOS stub. It often lists tool components used to produce the binary (not security-critical, and sometimes stripped).</div>`
  );

  out.push(`<dl>`);
  out.push(dd("Entries", String(rich.entries.length), "Number of decoded tool records."));
  out.push(dd("XOR key", hex(rich.xorKey, 8), "XOR key used to obfuscate the Rich header region."));
  if (rich.checksum != null) {
    out.push(dd("Checksum", hex(rich.checksum, 8), "Checksum field stored in the Rich header (best-effort)."));
  }
  out.push(`</dl>`);

  if (rich.warnings?.length) {
    out.push(
      `<div class="smallNote" style="color:var(--warn-fg)">${safe(rich.warnings.join(" \u2022 "))}</div>`
    );
  }

  if (!rich.entries.length) {
    out.push(`<div class="smallNote">No tool entries could be decoded.</div>`);
    out.push(`</section>`);
    return;
  }

  const byCount = [...rich.entries].sort((a, b) => b.count - a.count);
  const top = byCount.slice(0, 5);

  out.push(
    `<details><summary style="cursor:pointer;padding:.25rem .5rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg)">Show top entries (${top.length})</summary>`
  );
  out.push(
    `<table class="table" style="margin-top:.35rem"><thead><tr><th>#</th><th>Product</th><th>Build</th><th>Count</th><th>CompID</th></tr></thead><tbody>`
  );
  top.forEach((entry, index) => {
    out.push(
      `<tr><td>${index + 1}</td><td>${hex(entry.productId, 4)}</td><td>${hex(entry.buildNumber, 4)}</td><td>${entry.count}</td><td>${hex(formatCompId(entry), 8)}</td></tr>`
    );
  });
  out.push(`</tbody></table></details>`);

  if (rich.entries.length > top.length) {
    out.push(
      `<details style="margin-top:.35rem"><summary style="cursor:pointer;padding:.25rem .5rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg)">Show all entries (${rich.entries.length})</summary>`
    );
    out.push(
      `<table class="table" style="margin-top:.35rem"><thead><tr><th>#</th><th>Product</th><th>Build</th><th>Count</th><th>CompID</th></tr></thead><tbody>`
    );
    byCount.forEach((entry, index) => {
      out.push(
        `<tr><td>${index + 1}</td><td>${hex(entry.productId, 4)}</td><td>${hex(entry.buildNumber, 4)}</td><td>${entry.count}</td><td>${hex(formatCompId(entry), 8)}</td></tr>`
      );
    });
    out.push(`</tbody></table></details>`);
  }

  out.push(`</section>`);
}

