import assert from "node:assert/strict";
import { test } from "node:test";
import { DOMParser } from "@xmldom/xmldom";
import { renderVectorPreview } from "../../../../renderers/pe/resource-preview-vector.js";
void test("formats owned geometry and escapes text/attributes while retaining record evidence", () => {
  const html = renderVectorPreview({ format:"SVG", bounds:{x:-1,y:2,width:30,height:40}, nodes:[
    {tag:"text",attributes:[{name:"fill",value:'red" onload="bad'}],
      text:"<script>&<SCRIPT>alert(1)</SCRIPT foo=\"bar\">",children:[]}
  ], records:[{type:1,size:88,offset:0}] });
  assert.match(html, /viewBox="-1 2 30 40"/);
  assert.match(html, /&lt;script/);
  assert.match(html, /1 metafile records/);
  const document = new DOMParser().parseFromString(`<div>${html}</div>`, "text/html");
  assert.equal(document.getElementsByTagName("script").length, 0);
  assert.equal(document.getElementsByTagName("SCRIPT").length, 0);
  assert.equal(document.getElementsByTagName("text")[0]?.textContent,
    '<script>&<SCRIPT>alert(1)</SCRIPT foo="bar">');
  assert.equal(document.getElementsByTagName("text")[0]?.getAttribute("fill"), 'red" onload="bad');
  assert.equal(document.getElementsByTagName("text")[0]?.hasAttribute("onload"), false);
});
