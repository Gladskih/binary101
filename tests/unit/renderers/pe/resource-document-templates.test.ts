import assert from "node:assert/strict";
import { test } from "node:test";
import { renderResourceDocumentTemplates } from "../../../../renderers/pe/resource-document-templates.js";
void test("identifies possible document strings without claiming runtime usage", () => {
  const html = renderResourceDocumentTemplates({stringTable:[{id:100,text:"<Window>\nDoc\nNew\nFilter\n.bin"}]});
  assert.match(html, /Possible MFC document templates/);
  assert.match(html, /runtime use is unconfirmed/);
  assert.match(html, /&lt;Window/);
  assert.equal(renderResourceDocumentTemplates({}), "");
});
