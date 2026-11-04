import assert from "node:assert/strict";
import { test } from "node:test";
import { renderEmfRecord } from "../../../../../../analyzers/pe/resources/preview/emf-records.js";
import { createMetafileDrawing } from "../../../../../../analyzers/pe/resources/preview/metafile-drawing.js";
import { createEmfRecord } from "../../../../../fixtures/pe-resource-advanced-payloads.js";

const record = (type: number, words: number[]): DataView => {
  const payload = new Uint8Array(words.length * 4);
  const view = new DataView(payload.buffer);
  words.forEach((word,index) => view.setUint32(index * 4,word,true));
  const bytes = createEmfRecord(type,payload);
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.length);
};

void test("draws EMF geometry and maintains the device context", () => {
  const drawing = createMetafileDrawing([]);
  renderEmfRecord(record(38,[1,0,2,0,0xff]),drawing); // EMRCREATEPEN.
  renderEmfRecord(record(37,[1]),drawing);
  renderEmfRecord(record(27,[10,20]),drawing);
  renderEmfRecord(record(54,[30,40]),drawing);
  renderEmfRecord(record(43,[0,0,10,20]),drawing);
  renderEmfRecord(record(42,[0,0,10,20]),drawing);
  renderEmfRecord(record(40,[1]),drawing);

  assert.deepEqual(drawing.nodes.map(node=>node.tag),["line","rect","ellipse"]);
  assert.deepEqual(drawing.current.position,[30,40]);
  assert.equal(drawing.objects.size,0);
  assert.deepEqual(drawing.issues,[]);
});

void test("bounds-checks records, text and point arrays and retains unknown records", () => {
  const drawing = createMetafileDrawing([]);
  renderEmfRecord(new DataView(new ArrayBuffer(0)),drawing);
  renderEmfRecord(record(38,[]),drawing);
  renderEmfRecord(record(3,[0,0,0,0,999]),drawing);
  renderEmfRecord(record(999,[]),drawing);
  renderEmfRecord(record(43,[20,20,0,0]),drawing);

  assert.equal(drawing.nodes.length,0);
  assert.ok(drawing.omitted.has(999));
  assert.match(drawing.issues.join(" "), /header.*truncated.*point array.*reversed/su);
});

const wideTextRecord = (count: number, flags = 0): DataView => {
  const bytes = new Uint8Array(80);
  const view = new DataView(bytes.buffer);
  view.setUint32(0,84,true); view.setUint32(4,80,true);
  view.setInt32(36,10,true); view.setInt32(40,20,true); view.setUint32(44,count,true);
  view.setUint32(48,count ? 76 : 0,true); view.setUint32(52,flags,true);
  view.setUint16(76,65,true); view.setUint16(78,66,true);
  return view;
};
void test("renders UTF-16 EMF text and diagnoses glyph indices", () => {
  const drawing = createMetafileDrawing([]);
  renderEmfRecord(wideTextRecord(2),drawing);
  renderEmfRecord(wideTextRecord(2,16),drawing);
  assert.equal(drawing.nodes[0]?.text,"AB");
  assert.match(drawing.issues.join(" "),/glyph-index/);
});
void test("does not warn on a valid empty EMF text record with no string offset", () => {
  const drawing = createMetafileDrawing([]);
  renderEmfRecord(wideTextRecord(0),drawing);
  assert.deepEqual(drawing.issues,[]);
  assert.deepEqual(drawing.nodes,[]);
});

void test("maintains supported EMF mapping, objects, fonts and transforms", () => {
  const drawing = createMetafileDrawing([]);
  renderEmfRecord(record(9,[10,20]),drawing); renderEmfRecord(record(10,[1,2]),drawing);
  renderEmfRecord(record(11,[100,200]),drawing); renderEmfRecord(record(12,[3,4]),drawing);
  renderEmfRecord(record(17,[8]),drawing); renderEmfRecord(record(24,[255]),drawing);
  renderEmfRecord(record(39,[2,0,255,0]),drawing); renderEmfRecord(record(37,[2]),drawing);
  renderEmfRecord(record(82,[3,-12,0,0,0,400,0,0,65,...new Array<number>(15).fill(0)]),drawing);
  renderEmfRecord(record(37,[3]),drawing);
  renderEmfRecord(record(35,[0x3f800000,0,0,0x3f800000,0,0]),drawing);
  renderEmfRecord(record(33,[]),drawing); renderEmfRecord(record(34,[-1]),drawing);
  renderEmfRecord(record(3,[0,0,0,0,1,10,20]),drawing);
  renderEmfRecord(record(86,[0,0,0,0,1,0x0014000a]),drawing);

  assert.deepEqual(drawing.current.windowExtent,[10,20]);
  assert.deepEqual(drawing.current.windowOrigin,[1,2]);
  assert.deepEqual(drawing.current.viewportExtent,[100,200]);
  assert.deepEqual(drawing.current.viewportOrigin,[3,4]);
  assert.equal(drawing.current.mapMode,8);
  assert.equal(drawing.current.textColor,"#ff0000");
  assert.equal(drawing.current.font.family,"A");
  assert.equal(drawing.current.brush.color,"#ff0000");
  assert.equal(drawing.nodes.length,2);
  assert.deepEqual(drawing.issues,[]);
});
void test("keeps invalid transforms and text ranges out of the drawing", () => {
  const drawing = createMetafileDrawing([]);
  renderEmfRecord(record(35,[0x7fc00000,0,0,0,0,0]),drawing);
  renderEmfRecord(wideTextRecord(999),drawing);
  renderEmfRecord(wideTextRecord(0,2),drawing);
  assert.equal(drawing.nodes.length,0);
  assert.match(drawing.issues.join(" "),/not finite.*range.*approximated/su);
});
