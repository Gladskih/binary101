import assert from "node:assert/strict";
import { test } from "node:test";
import { renderDialogInitPreview, renderToolbarPreview } from "../../../../renderers/pe/resource-preview-mfc.js";

void test("renders MFC string initialization and unknown payload bytes safely", () => {
  const html = renderDialogInitPreview({ entries: [
    { controlId: 100, message: 0x403, data: new TextEncoder().encode("<item>\0") },
    { controlId: 101, message: 0x401, data: new TextEncoder().encode("other") },
    { controlId: 102, message: 0x1234, data: new Uint8Array([65, 0]) },
    { controlId: 103, message: 0xffff, data: new Uint8Array(33) }
  ] });

  assert.match(html, /CB_ADDSTRING \(Win16\)/);
  assert.match(html, /LB_ADDSTRING \(Win16\)/);
  assert.match(html, /AFX_CB_ADDSTRING/);
  assert.match(html, /&lt;item>/);
  assert.match(html, /41 00/);
  assert.match(html, / …/);
  assert.match(html, /Windows-1252/);
  assert.match(renderDialogInitPreview({ entries: [] }), /<tbody><\/tbody>/);
});

void test("renders toolbar command order and separators", () => {
  const html = renderToolbarPreview({ version: 1, width: 16, height: 15, items: [100, 0, 101] });
  assert.match(html, /16×15/);
  assert.match(html, /#100.*Separator.*#101/);
});
