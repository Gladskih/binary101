import assert from "node:assert/strict";
import { test } from "node:test";
import { createMetafileDrawing, metafileColor, addDrawingNode, selectDrawingObject,
  restoreDrawingState } from "../../../../../../analyzers/pe/resources/preview/metafile-drawing.js";

void test("applies GDI pens, brushes, stock objects, transforms and saved states", () => {
  const drawing = createMetafileDrawing([]);
  drawing.objects.set(1, {kind:"pen",color:"#ff0000",width:3,style:1});
  selectDrawingObject(drawing, 1);
  selectDrawingObject(drawing, 0x80000005); // NULL_BRUSH, wingdi.h.
  drawing.current.mapMode = 8;
  drawing.current.windowExtent = [10, 20]; drawing.current.viewportExtent = [100, 100];
  drawing.saved.push({...drawing.current});
  addDrawingNode(drawing, "rect", {x:0,y:0,width:10,height:20});
  drawing.current = {...drawing.current, position:[3,4]};
  restoreDrawingState(drawing, -1);

  assert.equal(metafileColor(0x000000ff), "#ff0000");
  assert.equal(drawing.nodes[0]?.attributes.find(item=>item.name === "fill")?.value, "none");
  assert.equal(drawing.nodes[0]?.attributes.find(item=>item.name === "stroke")?.value, "#ff0000");
  assert.match(drawing.nodes[0]?.attributes.find(item=>item.name === "transform")?.value ?? "", /matrix\(10 0 0 5/);
  assert.deepEqual(drawing.current.position, [0,0]);
});

void test("diagnoses unknown handles, invalid saved states and unsupported mapping modes", () => {
  const issues: string[] = [];
  const drawing = createMetafileDrawing(issues);
  selectDrawingObject(drawing, 999);
  selectDrawingObject(drawing, 0x800000ff);
  restoreDrawingState(drawing, 1);
  drawing.current.mapMode = 8; drawing.current.windowExtent = [0,0];
  addDrawingNode(drawing,"line",{});
  drawing.current.mapMode = 2;
  addDrawingNode(drawing,"line",{});

  assert.equal(drawing.nodes.length,0);
  assert.match(issues.join(" "), /unknown object.*stock object.*unknown DC.*zero window.*fixed-unit/su);
});
