"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderTls, renderIat } from "../../renderers/pe/directories.js";

void test("renderTls and renderIat display local directory warnings", () => {
  const tls: Parameters<typeof renderTls>[0] = {
    StartAddressOfRawData: 0n,
    EndAddressOfRawData: 0n,
    AddressOfIndex: 0n,
    AddressOfCallBacks: 0n,
    SizeOfZeroFill: 0,
    Characteristics: 0,
    CallbackCount: 0,
    CallbackRvas: [],
    warnings: ["TLS directory RVA could not be mapped to a file offset."],
    parsed: false
  };
  const iat: Parameters<typeof renderIat>[0] = {
    rva: 0x1000,
    size: 0x20,
    warnings: ["IAT directory RVA could not be mapped to a file offset."]
  };

  const out: string[] = [];
  renderTls(tls, out);
  renderIat(iat, out);
  const html = out.join("");

  assert.ok(html.includes("TLS directory RVA could not be mapped to a file offset."));
  assert.ok(html.includes("IAT directory RVA could not be mapped to a file offset."));
});
