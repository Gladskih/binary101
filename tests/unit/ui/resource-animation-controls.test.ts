import assert from "node:assert/strict";
import { test } from "node:test";
import { handleResourceAnimationClick } from "../../../ui/resource-animation-controls.js";

const animationDom = () => {
  const globals = globalThis as unknown as Record<string, unknown>;
  const originals = ["Element","requestAnimationFrame","cancelAnimationFrame"].map(name => [name,globals[name]] as const);
  const frames = [{hidden:false},{hidden:true}];
  const status = {textContent:""};
  const callbacks = new Map<number,FrameRequestCallback>();
  let next = 1;
  const root = {isConnected:true,dataset:{peAnimationSteps:"1:100,0:200"},
    querySelector:()=>status,querySelectorAll:()=>frames};
  class Target {
    textContent = "Play";
    closest(selector: string): unknown { return selector === "[data-pe-animation]" ? root : this; }
  }
  const button = new Target();
  globals["Element"] = Target;
  globals["requestAnimationFrame"] = (callback:FrameRequestCallback) => {
    const id = next++; callbacks.set(id,callback); return id;
  };
  globals["cancelAnimationFrame"] = (id:number) => { callbacks.delete(id); };
  return {root,button,status,frames,callbacks,event:{target:button} as never,
    restore:()=>originals.forEach(([name,value])=>{globals[name]=value;})};
};

void test("plays ANI steps and stops the scheduled animation on a second click", context => {
  const fixture = animationDom();
  context.after(fixture.restore);

  handleResourceAnimationClick(fixture.event);
  fixture.callbacks.get(1)!(performance.now()+1);
  assert.equal(fixture.button.textContent,"Pause");
  assert.deepEqual(fixture.frames.map(frame=>frame.hidden),[true,false]);
  assert.match(fixture.status.textContent,/Step 1 \/ 2; frame 2/);
  handleResourceAnimationClick(fixture.event);
  assert.equal(fixture.button.textContent,"Play");
  assert.equal(fixture.status.textContent,"Stopped");
});

void test("rejects invalid sequence/timing and stops when the resource is removed", context => {
  const fixture = animationDom();
  context.after(fixture.restore);
  fixture.root.dataset.peAnimationSteps = "99:0";

  handleResourceAnimationClick(fixture.event);
  assert.match(fixture.status.textContent,/unavailable/);
  assert.equal(fixture.callbacks.size,0);
  fixture.root.dataset.peAnimationSteps = "0:100";
  handleResourceAnimationClick(fixture.event);
  fixture.root.isConnected = false;
  fixture.callbacks.get(1)!(performance.now()+1);
  assert.equal(fixture.callbacks.size,1);
  handleResourceAnimationClick({target:null} as never);
});
