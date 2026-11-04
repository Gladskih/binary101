import assert from "node:assert/strict";
import { test } from "node:test";
import { ribbonChild, ribbonChildren, ribbonValue, ribbonCommandKey, ribbonImageUrl,
  renderRibbonElements } from "../../../../renderers/pe/ribbon-elements.js";
import { parseXmlTree } from "../../../../analyzers/pe/resources/preview/xml-tree.js";
import { parseManifestTestXmlDocument } from "../../../helpers/manifest-test-parser.js";
import { linkedDialogPreview } from "../../../helpers/pe-resource-linked-preview.js";
import { expectDefined } from "../../../helpers/expect-defined.js";

const element = (xml: string) => expectDefined(parseXmlTree(parseManifestTestXmlDocument(xml)));

void test("preserves numeric and symbolic Ribbon IDs without inventing absent values", () => {
  const node = element('<ELEMENT><ID><NAME>Command</NAME><VALUE>100</VALUE></ID><TEXT>Open</TEXT></ELEMENT>');

  assert.equal(ribbonCommandKey(node),100);
  assert.equal(ribbonCommandKey(element('<ELEMENT><ID><NAME>Named</NAME></ID></ELEMENT>')),"Named");
  assert.equal(ribbonCommandKey(element('<ELEMENT/>')),null);
  assert.equal(ribbonValue(node,"TEXT"),"Open");
  assert.equal(ribbonChildren(undefined,"ELEMENT").length,0);
  assert.equal(ribbonChild(undefined,"ID"),undefined);
});

void test("renders owned images, image strips, galleries and saved control variants", () => {
  const context = linkedDialogPreview();
  const image = element('<IMAGE><ID><VALUE>1</VALUE></ID></IMAGE>');
  const nodes = [
    element('<ELEMENT><ELEMENT_NAME>Button</ELEMENT_NAME><TEXT>Open</TEXT><KEYS>O</KEYS><IMAGE>'+
      '<ID><VALUE>1</VALUE></ID></IMAGE><ITEMS><ITEM>Choice</ITEM></ITEMS></ELEMENT>'),
    element('<ELEMENT><ELEMENT_NAME>Gallery</ELEMENT_NAME><INDEX_LARGE>0</INDEX_LARGE>'+
      '<GROUPS><GROUP><NAME>Group</NAME><ITEMS>3</ITEMS></GROUP></GROUPS></ELEMENT>'),
    element('<ELEMENT><ELEMENT_NAME>ComboBox</ELEMENT_NAME><INDEX_SMALL>0</INDEX_SMALL></ELEMENT>'),
    element('<ELEMENT><ELEMENT_NAME>Edit</ELEMENT_NAME><VALUE>&lt;text&gt;</VALUE></ELEMENT>'),
    element('<ELEMENT><ELEMENT_NAME>Slider</ELEMENT_NAME></ELEMENT>'),
    element('<ELEMENT><ELEMENT_NAME>Progress</ELEMENT_NAME></ELEMENT>'),
    element('<ELEMENT><ELEMENT_NAME>Button_Check</ELEMENT_NAME></ELEMENT>'),
    element('<ELEMENT><ELEMENT_NAME>Separator</ELEMENT_NAME></ELEMENT>')
  ];
  const html = renderRibbonElements(nodes,{small:image,large:image},context);

  assert.equal(ribbonImageUrl(image,context),"data:image/png;base64,AQ==");
  assert.equal(ribbonImageUrl(element('<IMAGE><ID><VALUE>0</VALUE></ID></IMAGE>'),context),undefined);
  assert.match(html,/peRibbon__ownImage/);
  assert.match(html,/width:32px;height:32px/);
  assert.match(html,/width:16px;height:16px/);
  assert.match(html,/Choice/);
  assert.match(html,/Group: 3 items/);
  assert.match(html,/&lt;text/);
  assert.match(html,/<hr/);
});
