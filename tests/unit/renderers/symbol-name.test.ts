import assert from "node:assert/strict";
import { test } from "node:test";
import { renderSymbolName } from "../../../renderers/symbol-name.js";

void test("unchanged symbol names preserve literal entities and escape markup", () => {
  assert.equal(renderSymbolName("<>&lt;", "<>&lt;"), "&lt;>&amp;lt;");
});

void test("decoded presentation escapes both names and retains the linker spelling", () => {
  assert.equal(renderSymbolName("_Z<script>&lt;", "Box<int>&lt;"),
    '<code>Box&lt;int>&amp;lt;</code><br><code class="dim">_Z&lt;script>&amp;lt;</code>');
});
