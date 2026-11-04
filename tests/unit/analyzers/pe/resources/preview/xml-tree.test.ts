import assert from "node:assert/strict";
import { test } from "node:test";
import { parseXmlTree, getXmlLocalTagName } from "../../../../../../analyzers/pe/resources/preview/xml-tree.js";
import { parseManifestTestXmlDocument } from "../../../../../helpers/manifest-test-parser.js";

const treeDepth = (tree: ReturnType<typeof parseXmlTree>): number => {
  let depth = 0;
  for (let node = tree; node; node = node.children[0] ?? null) depth += 1;
  return depth;
};

void test("converts deeply nested XML into plain data without recursion", () => {
  const depth = 2000;
  const xml = "<Node>".repeat(depth)+"value"+"</Node>".repeat(depth);
  const tree = parseXmlTree(parseManifestTestXmlDocument(xml));

  assert.equal(treeDepth(tree),depth);
  assert.equal(tree?.name,"Node");
});

void test("preserves direct text, CDATA, children and attributes independently", () => {
  const tree = parseXmlTree(parseManifestTestXmlDocument('<ns:Root xmlns:ns="urn:test" id="A"> Direct '+
    '<Child>Nested</Child><![CDATA[Tail]]></ns:Root>'));

  assert.equal(tree?.text,"Direct Tail");
  assert.equal(tree?.children[0]?.text,"Nested");
  assert.deepEqual(tree?.attributes.map(item=>[item.name,item.value]),[["xmlns:ns","urn:test"],["id","A"]]);
  assert.equal(getXmlLocalTagName("ns:Root"),"root");
  assert.equal(parseXmlTree({documentElement:null,getElementsByTagName:()=>[] as never}),null);
  assert.equal(parseXmlTree(parseManifestTestXmlDocument("<parsererror/>")),null);
});
