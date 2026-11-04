import assert from "node:assert/strict";
import { test } from "node:test";
import { createPeResourcePayloadClickHandler } from "../../../ui/pe-resource-payload-actions.js";
import { createPreviewLangEntry, createPreviewDetailGroup } from "../../helpers/pe-resource-preview-fixture.js";
import { createPngFile } from "../../fixtures/image-sample-files.js";
import { MockFile } from "../../helpers/mock-file.js";
import type { ParseForUiResult } from "../../../analyzers/index.js";

const payloadDom = () => {
  const globals = globalThis as unknown as Record<string,unknown>;
  const previous = globals["Element"];
  const container = {innerHTML:""};
  class Button {
    disabled = false;
    dataset = {peResourcePreview:"0-0-0"};
    closest(selector:string): unknown { return selector === "[data-pe-resource-preview-content]" ? container : this; }
  }
  globals["Element"] = Button;
  const button = new Button();
  const file = new MockFile(createPngFile().data);
  const leaf = {...createPreviewLangEntry(0,file.size),previewKind:"deferred"};
  const result = {analyzer:"pe",parsed:{resources:{top:[],detail:[createPreviewDetailGroup("RCDATA",1,leaf)]},
    rvaToOff:(rva:number)=>rva}} as unknown as ParseForUiResult;
  const messages: Array<string | null | undefined> = [];
  return {container,button,result,file,messages,leaf,event:{target:button} as never,
    handler:createPeResourcePayloadClickHandler(()=>result,()=>file,message=>{messages.push(message);}),
    restore:()=>{globals["Element"]=previous;}};
};

void test("loads deferred media locally and replaces only its own preview", async context => {
  const fixture = payloadDom();
  context.after(fixture.restore);

  await fixture.handler(fixture.event);
  assert.match(fixture.container.innerHTML,/data:image\/png;base64/);
  assert.equal(fixture.button.disabled,false);
  assert.deepEqual(fixture.messages,[null]);
  assert.equal(fixture.leaf.previewKind,"deferred");
});

void test("ignores invalid coordinates and visibly reports unreadable bytes", async context => {
  const fixture = payloadDom();
  context.after(fixture.restore);
  fixture.button.dataset.peResourcePreview = "-1-0-0";

  await fixture.handler(fixture.event);
  assert.equal(fixture.messages.length,0);
  fixture.button.dataset.peResourcePreview = "0-0-0";
  fixture.leaf.dataFileOffset = null;
  await fixture.handler(fixture.event);
  assert.match(fixture.messages.join(" "),/failed/);
  assert.equal(fixture.button.disabled,false);
});
