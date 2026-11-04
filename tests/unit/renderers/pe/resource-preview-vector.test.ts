import assert from "node:assert/strict";
import { test } from "node:test";
import { renderVectorPreview } from "../../../../renderers/pe/resource-preview-vector.js";
void test("formats owned geometry and escapes text/attributes while retaining record evidence", () => {
  const html = renderVectorPreview({ format:"SVG", bounds:{x:-1,y:2,width:30,height:40}, nodes:[
    {tag:"text",attributes:[{name:"fill",value:'red" onload="bad'}], text:"<script>&",children:[]}
  ], records:[{type:1,size:88,offset:0}] });
  assert.match(html, /viewBox="-1 2 30 40"/);
  assert.match(html, /&lt;script/);
  assert.match(html, /1 metafile records/);
  assert.doesNotMatch(html, /<script>/);
});
