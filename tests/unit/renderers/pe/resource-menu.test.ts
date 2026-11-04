import assert from "node:assert/strict";
import { test } from "node:test";
import { renderMenuResourceItems } from "../../../../renderers/pe/resource-menu.js";
void test("renders nested menus, flags and unnamed separators without interpreting source text", () => {
  const html = renderMenuResourceItems([{text:"<File>",id:null,type:null,state:null,flags:["checked"],children:[
    {text:null,id:9,type:null,state:null,flags:[],children:[]}]}]);
  assert.match(html, /&lt;File/);
  assert.match(html, /checked/);
  assert.match(html, /#9/);
  assert.match(html, /separator or unnamed/);
  assert.match(renderMenuResourceItems([]), /empty menu/);
});
