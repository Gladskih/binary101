import assert from "node:assert/strict";
import { test } from "node:test";
import type { ResourceXmlTreeNode } from "../../../../analyzers/pe/resources/preview/types.js";
import { renderRibbonXmlPreview } from "../../../../renderers/pe/resource-preview-ribbon-xml.js";

const node = (name: string, children: ResourceXmlTreeNode[] = [], text: string | null = null):
  ResourceXmlTreeNode => ({ name, attributes: [], text, children });

void test("renders MFC categories, panels and command IDs above the complete XML tree", () => {
  // Structure from krb5's original ribbon1.mfcribbon-ms MFC resource.
  const tree = node("RIBBON_BAR", [
    node("BUTTON_MAIN", [node("ELEMENT_NAME", [], "Button_Main"),
      node("ID", [node("NAME", [], "ID_FILE")])]),
    node("CATEGORY_MAIN", [node("NAME", [], "File"), node("ELEMENTS", [
      node("ELEMENT", [node("ELEMENT_NAME", [], "Button"),
        node("TEXT", [], "<Exit>"), node("ID", [node("NAME", [], "ID_EXIT")])])
    ])]),
    node("CATEGORIES", [node("CATEGORY", [node("NAME", [], "Home"),
      node("PANELS", [node("PANEL", [node("NAME", [], "Edit"),
        node("ELEMENTS", [node("ELEMENT", [node("ELEMENT_NAME", [], "Button_Check"),
          node("TEXT", [], "<Toggle>"), node("ID", [node("NAME", [], "ID_TOGGLE")])])])
      ])])
    ])])
  ]);
  const html = renderRibbonXmlPreview(undefined, tree);
  assert.match(html, /2 categories, 3 controls/);
  assert.match(html, /Application button.*ID_FILE/);
  assert.match(html, /File.*&lt;Exit>.*ID_EXIT/);
  assert.match(html, /Home.*Edit.*Button_Check.*&lt;Toggle>.*ID_TOGGLE/);
  assert.match(html, /Parsed XML tree/);
});

void test("preserves generic XML and empty Ribbon trees", () => {
  assert.match(renderRibbonXmlPreview("<other/>", node("other")), /Parsed XML tree/);
  assert.doesNotMatch(renderRibbonXmlPreview("<other/>", node("other")), /MFC Ribbon:/);
  assert.match(renderRibbonXmlPreview(undefined, node("RIBBON_BAR")), /0 categories, 0 controls/);
});

void test("labels unnamed MFC ribbon controls and numeric command IDs", () => {
  const tree = node("RIBBON_BAR", [node("BUTTON_MAIN"),
    node("CATEGORIES", [node("CATEGORY", [node("PANELS", [node("PANEL", [
      node("ELEMENTS", [node("ELEMENT", [node("ID", [node("VALUE", [], "42")])])])
    ])])])])]);
  const html = renderRibbonXmlPreview(undefined, tree);
  assert.match(html, /Application button.*Button/);
  assert.match(html, /\(unnamed category\).*\(unnamed panel\).*Element/);
  assert.match(html, /42/);
});
