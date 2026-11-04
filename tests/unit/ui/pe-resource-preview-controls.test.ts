import assert from "node:assert/strict";
import { test } from "node:test";
import { handlePeResourcePreviewClick, enhancePeResourcePreviews,
  handleResourcePreviewRendered } from "../../../ui/pe-resource-preview-controls.js";
import type { ParseForUiResult } from "../../../analyzers/index.js";

const ribbonDom = () => {
  const globals = globalThis as unknown as Record<string,unknown>;
  const original = globals["Element"];
  const tabs = [{selected:""},{selected:""}];
  const panels = [{hidden:false,dataset:{peRibbonPanel:"0"}},{hidden:true,dataset:{peRibbonPanel:"1"}}];
  const ribbon = {querySelectorAll:(selector:string) => selector === "[data-pe-ribbon-tab]"
    ? tabs.map((tab,index)=>index === 1 ? button : {setAttribute:(_name:string,value:string)=>{tab.selected=value;}})
    : panels};
  const button = {dataset:{peRibbonTab:"1"},closest:()=>ribbon,
    setAttribute:(_name:string,value:string)=>{tabs[1]!.selected=value;}};
  class Target { closest(selector:string): unknown { return selector === "[data-pe-ribbon-tab]" ? button : null; } }
  globals["Element"] = Target;
  return {tabs,panels,event:{target:new Target()} as never,restore:()=>{globals["Element"]=original;}};
};

void test("switches Ribbon tabs without invoking application commands", context => {
  const fixture = ribbonDom();
  context.after(fixture.restore);

  handlePeResourcePreviewClick(fixture.event,{analyzer:"unknown",parsed:{}} as never);
  assert.deepEqual(fixture.tabs.map(tab=>tab.selected),["false","true"]);
  assert.deepEqual(fixture.panels.map(panel=>panel.hidden),[true,false]);
  handlePeResourcePreviewClick({target:null} as never,{} as never);
});

const dialogDom = () => {
  const globals = globalThis as unknown as Record<string,unknown>;
  const names = ["Element","HTMLElement","HTMLInputElement","getComputedStyle","ResizeObserver"];
  const originals = names.map(name=>[name,globals[name]] as const);
  const listeners = new Map<string,(event:never)=>void>();
  const properties = new Map<string,string>();
  const toggles = new Map<string,boolean>();
  const client = {clientWidth:120,clientHeight:100};
  const window = {style:{setProperty:(key:string,value:string)=>{properties.set(key,value);}}};
  const dialog = {isConnected:true,dataset:{peDialogWidth:"40",peDialogHeight:"50",peDialogReady:""},
    ownerDocument:{createElement:()=>({getContext:()=>({font:"",measureText:()=>({width:208,
      fontBoundingBoxAscent:12,fontBoundingBoxDescent:4})})})},
    style:window.style,querySelector:(selector:string)=>selector === ".peDialog__window" ? window : client,
    addEventListener:(name:string,callback:(event:never)=>void)=>{listeners.set(name,callback);},
    toggleAttribute:(name:string,value:boolean)=>{toggles.set(name,value);}};
  let resize = () => {};
  class Input {
    checked = true;
    value = "150";
    closest(): unknown { return dialog; }
    hasAttribute(): boolean { return true; }
  }
  globals["Element"] = Input; globals["HTMLElement"] = Input; globals["HTMLInputElement"] = Input;
  globals["getComputedStyle"] = ()=>({fontStyle:"normal",fontWeight:"400",fontSize:"16px",fontFamily:"Arial"});
  globals["ResizeObserver"] = class {
    constructor(callback:()=>void) {resize=callback;}
    observe(): void {}
    disconnect(): void {}
  };
  return {dialog,root:{querySelectorAll:()=>[dialog]} as never,listeners,properties,toggles,
    input:new Input(),resize:()=>resize(),restore:()=>originals.forEach(([name,value])=>{globals[name]=value;})};
};

void test("measures dialog units and applies resize, zoom and visibility controls", context => {
  const fixture = dialogDom();
  context.after(fixture.restore);

  enhancePeResourcePreviews(fixture.root);
  fixture.resize();
  fixture.listeners.get("input")!({target:fixture.input} as never);
  assert.equal(fixture.dialog.dataset.peDialogReady,"true");
  assert.equal(fixture.properties.get("--pe-dlu-x"),"1px");
  assert.equal(fixture.properties.get("--pe-dlu-y"),"2px");
  assert.equal(fixture.properties.get("--pe-dialog-dx"),"80px");
  assert.equal(fixture.properties.get("--pe-dialog-dy"),"0px");
  assert.equal(fixture.properties.get("zoom"),"1.5");
  assert.equal(fixture.toggles.get("data-show-tab-order"),true);
  assert.equal(fixture.toggles.get("data-hide-invisible"),false);
  fixture.dialog.isConnected=false;
  fixture.resize();
  handleResourcePreviewRendered({target:null} as never);
});

void test("opens a validated referenced resource and selects its anchor", context => {
  const globals = globalThis as unknown as Record<string,unknown>;
  const original = globals["Element"];
  context.after(()=>{globals["Element"]=original;});
  let scrolled = false;
  const container = {tagName:"DETAILS",parentElement:null,open:false,querySelector:()=>null};
  const link = {dataset:{peResourceTarget:"0-0-0"},ownerDocument:{querySelector:()=>container,
    getElementById:()=>({scrollIntoView:()=>{scrolled=true;}})}};
  class Target { closest(selector:string): unknown {return selector === "[data-pe-resource-target]" ? link : null;} }
  globals["Element"]=Target;
  const result = {analyzer:"pe",parsed:{resources:{detail:[{entries:[{langs:[{}]}]}]}}} as unknown as ParseForUiResult;

  handlePeResourcePreviewClick({target:new Target(),preventDefault:()=>{}} as never,result);
  assert.equal(container.open,true);
  assert.equal(scrolled,true);
});
