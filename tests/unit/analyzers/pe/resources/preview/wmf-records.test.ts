import assert from "node:assert/strict";
import { test } from "node:test";
import { renderWmfRecord } from "../../../../../../analyzers/pe/resources/preview/wmf-records.js";
import { createMetafileDrawing } from "../../../../../../analyzers/pe/resources/preview/metafile-drawing.js";
import { createWmfRecord } from "../../../../../fixtures/pe-resource-advanced-payloads.js";

const record = (type: number, words: number[]): DataView => {
  const payload = new Uint8Array(words.length * 2);
  const view = new DataView(payload.buffer);
  words.forEach((word,index) => view.setUint16(index * 2,word,true));
  const bytes = createWmfRecord(type,payload);
  return new DataView(bytes.buffer,bytes.byteOffset,bytes.length);
};

void test("allocates first-free WMF objects and draws in documented y,x order", () => {
  const drawing = createMetafileDrawing([]);
  renderWmfRecord(record(0x02fa,[0,2,0,255,0]),drawing);
  renderWmfRecord(record(0x012d,[0]),drawing);
  renderWmfRecord(record(0x0214,[20,10]),drawing);
  renderWmfRecord(record(0x0213,[40,30]),drawing);
  renderWmfRecord(record(0x041b,[20,10,0,0]),drawing);
  renderWmfRecord(record(0x01f0,[0]),drawing);
  renderWmfRecord(record(0x02fc,[0,255,0,0]),drawing);

  assert.deepEqual(drawing.current.position,[30,40]);
  assert.deepEqual(drawing.nodes.map(node=>node.tag),["line","rect"]);
  assert.equal(drawing.objects.get(0)?.kind,"brush");
  assert.deepEqual(drawing.issues,[]);
});

void test("reports truncated WMF records and malformed variable arrays", () => {
  const drawing = createMetafileDrawing([]);
  renderWmfRecord(new DataView(new ArrayBuffer(0)),drawing);
  renderWmfRecord(record(0x02fa,[]),drawing);
  renderWmfRecord(record(0x0324,[999]),drawing);
  renderWmfRecord(record(0x0521,[999]),drawing);
  renderWmfRecord(record(0xffff,[]),drawing);

  assert.equal(drawing.nodes.length,0);
  assert.ok(drawing.omitted.has(0xffff));
  assert.match(drawing.issues.join(" "), /header.*truncated.*point array.*text/su);
});

void test("renders WMF point arrays, ellipses and counted ANSI text", () => {
  const drawing = createMetafileDrawing([]);
  renderWmfRecord(record(0x0418,[20,10,0,0]),drawing);
  renderWmfRecord(record(0x0324,[1,10,20]),drawing);
  renderWmfRecord(record(0x0325,[1,10,20]),drawing);
  renderWmfRecord(record(0x0521,[2,0x4241,20,10]),drawing);
  renderWmfRecord(record(0x020b,[2,1]),drawing); renderWmfRecord(record(0x020c,[20,10]),drawing);
  renderWmfRecord(record(0x020d,[4,3]),drawing); renderWmfRecord(record(0x020e,[200,100]),drawing);
  renderWmfRecord(record(0x0103,[8]),drawing);
  renderWmfRecord(record(0x001e,[]),drawing); renderWmfRecord(record(0x0127,[0xffff]),drawing);
  renderWmfRecord(record(0x0209,[255,0]),drawing);
  renderWmfRecord(record(0x012d,[0x8008]),drawing); // NULL_PEN stock object.

  assert.deepEqual(drawing.nodes.map(node=>node.tag),["ellipse","polygon","polyline","text"]);
  assert.equal(drawing.nodes[3]?.text,"AB");
  assert.deepEqual(drawing.current.windowOrigin,[1,2]);
  assert.deepEqual(drawing.current.viewportExtent,[100,200]);
  assert.equal(drawing.current.textColor,"#ff0000");
  assert.equal(drawing.current.pen.style,5);
  assert.match(drawing.issues.join(" "),/Windows-1252/);
});
