import assert from "node:assert/strict";
import { test } from "node:test";
import { renderDfmPreview } from "../../../../renderers/pe/resource-preview-dfm.js";
import { addDfmPreview } from "../../../../analyzers/pe/resources/preview/dfm.js";
import { createDfmResource } from "../../../fixtures/pe-resource-advanced-payloads.js";
import { expectDefined } from "../../../helpers/expect-defined.js";
void test("renders saved DFM geometry with component/property evidence and escaped captions", () => {
  const root = expectDefined(addDfmPreview(createDfmResource())?.preview?.dfm);
  root.children[0]!.properties.push({name:"Text",value:{kind:"string",value:"<img src=x>"}});
  const html = renderDfmPreview(root);
  assert.match(html, /Main.Accept/);
  assert.match(html, /left:12px;top:16px/);
  assert.match(html, /&lt;img/);
  assert.doesNotMatch(html, /<img src=x>/);
});

void test("renders the retained form value kinds and known component faces", () => {
  const root = expectDefined(addDfmPreview(createDfmResource())?.preview?.dfm);
  root.properties.push({name:"Raw",value:{kind:"binary",data:new Uint8Array(33)}},
    {name:"Extended",value:{kind:"extended",value:"00000000000000000000"}},
    {name:"Null",value:{kind:"null"}},{name:"Set",value:{kind:"set",values:["One"]}},
    {name:"List",value:{kind:"list",values:[]}},{name:"Items",value:{kind:"collection",items:[]}});
  root.children = ["TCheckBox","TCheckBox","TRadioButton","TProgressBar","TComboBox","TCustom"].map((className,index)=>({
    className,name:"Control"+index,flags:0,children:[],properties:[
      {name:"Checked",value:{kind:"boolean",value:index===0}},
      {name:"Left",value:{kind:"number",value:"Infinity"}},
      {name:"Text",value:{kind:"string",value:"Text"}}
    ]
  }));
  const html = renderDfmPreview(root);

  assert.match(html,/33 bytes/);
  assert.match(html,/x87 extended/);
  assert.match(html,/nil/);
  assert.match(html,/0 list items/);
  assert.match(html,/0 collection items/);
  assert.match(html,/<progress/);
  assert.doesNotMatch(html,/left:Infinity/);
});
