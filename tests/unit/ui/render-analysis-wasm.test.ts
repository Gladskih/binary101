import assert from "node:assert/strict";
import { test } from "node:test";
import { parseForUi } from "../../../analyzers/index.js";
import { renderAnalysisIntoUi } from "../../../ui/render-analysis.js";
import { createWasmFile } from "../../fixtures/wasm-fixtures.js";

void test("renderAnalysisIntoUi renders deep WebAssembly analysis", async () => {
  const termElement = { textContent: "", hidden: true } as unknown as HTMLElement;
  const valueElement = { innerHTML: "", hidden: true } as unknown as HTMLElement;
  renderAnalysisIntoUi(await parseForUi(createWasmFile()), {
    buildPreview: () => null, attachGuards: () => {}, termElement, valueElement
  });
  assert.equal(termElement.textContent, "WebAssembly details");
  assert.equal(valueElement.hidden, false);
  assert.match(valueElement.innerHTML, /i32.add/);
});
