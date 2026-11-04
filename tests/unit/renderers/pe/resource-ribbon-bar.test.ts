import assert from "node:assert/strict";
import { test } from "node:test";
import { renderResourceRibbonBar } from "../../../../renderers/pe/resource-ribbon-bar.js";
import { parseXmlTree } from "../../../../analyzers/pe/resources/preview/xml-tree.js";
import { parseManifestTestXmlDocument } from "../../../helpers/manifest-test-parser.js";
import { expectDefined } from "../../../helpers/expect-defined.js";
import { interactiveRibbonXml } from "../../../fixtures/pe-resource-interactive-payloads.js";

void test("renders native MFC tabs, nested controls and the saved quick access items", () => {
  const tree = expectDefined(parseXmlTree(parseManifestTestXmlDocument(interactiveRibbonXml)));
  const ribbon = expectDefined(tree.children.find(child => child.name === "RIBBON_BAR"));
  const html = renderResourceRibbonBar(ribbon);

  assert.match(html, /role="tab"[^>]*>Home/);
  assert.match(html, /role="tab"[^>]*>View/);
  assert.match(html, /Nested choice/);
  assert.match(html, /peRibbon__quick[^]*Open/);
  assert.doesNotMatch(html, /peRibbon__quick"><\/div>/);
});
