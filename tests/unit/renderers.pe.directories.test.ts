"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderTls, renderIat } from "../../renderers/pe/directories.js";
import type { PeParseResult } from "../../analyzers/pe/index.js";

void test("renderTls and renderIat display local directory warnings", () => {
  const pe = {
    tls: {
      StartAddressOfRawData: 0,
      EndAddressOfRawData: 0,
      AddressOfIndex: 0,
      AddressOfCallBacks: 0,
      SizeOfZeroFill: 0,
      Characteristics: 0,
      CallbackCount: 0,
      CallbackRvas: [],
      warnings: ["TLS directory RVA could not be mapped to a file offset."],
      parsed: false
    },
    iat: {
      rva: 0x1000,
      size: 0x20,
      warnings: ["IAT directory RVA could not be mapped to a file offset."]
    }
  } as unknown as PeParseResult;

  const out: string[] = [];
  renderTls(pe, out);
  renderIat(pe, out);
  const html = out.join("");

  assert.ok(html.includes("TLS directory RVA could not be mapped to a file offset."));
  assert.ok(html.includes("IAT directory RVA could not be mapped to a file offset."));
});
