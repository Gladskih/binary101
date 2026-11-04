import assert from "node:assert/strict";
import { test } from "node:test";
import { DfmReader, readDfmValue } from "../../../../../../analyzers/pe/resources/preview/dfm-values.js";
import { joinResourceBytes, resourceDword, dfmShortString } from "../../../../../fixtures/pe-resource-advanced-payloads.js";

const valueReader = (data: Uint8Array): DfmReader => new DfmReader(joinResourceBytes(new Uint8Array(4), data));

void test("reads nested lists, sets and collection properties", () => {
  const reader = valueReader(joinResourceBytes(Uint8Array.of(1, 11), dfmShortString("akLeft"),
    Uint8Array.of(0, 14, 1), dfmShortString("Name"), Uint8Array.of(6), dfmShortString("First"),
    Uint8Array.of(0, 0, 0)));

  assert.deepEqual(readDfmValue(reader), { kind: "list", values: [
    { kind: "set", values: ["akLeft"] }, { kind: "collection", items: [[
      { name: "Name", value: { kind: "string", value: "First" } }
    ]] }
  ] });
});

void test("checks binary lengths and retains unsigned 64-bit integers exactly", () => {
  const binary = valueReader(joinResourceBytes(Uint8Array.of(10), resourceDword(2), Uint8Array.of(1)));
  const integer = valueReader(Uint8Array.of(22, 255, 255, 255, 255, 255, 255, 255, 255));

  assert.throws(() => readDfmValue(binary), /truncated/);
  assert.deepEqual(readDfmValue(integer), { kind: "number", value: "18446744073709551615" });
  assert.throws(() => readDfmValue(valueReader(Uint8Array.of(255))), /unsupported/);
});

const numericPayload = (tag: number): Uint8Array => {
  const sizes = new Map([[2,1],[3,2],[4,4],[5,10],[15,4],[16,8],[17,8],[19,8],[22,8],[23,8]]);
  const bytes = new Uint8Array(sizes.get(tag)!);
  const view = new DataView(bytes.buffer);
  if (tag === 2) view.setInt8(0,-1);
  else if (tag === 3) view.setInt16(0,-2,true);
  else if (tag === 4) view.setInt32(0,-3,true);
  else if (tag === 5) bytes.set([0,1,2,3,4,5,6,7,8,9]);
  else if (tag === 15) view.setFloat32(0,1.5,true);
  else if (tag === 16) view.setBigInt64(0,10001n,true);
  else if (tag === 19) view.setBigInt64(0,-42n,true);
  else if (tag === 22) view.setBigUint64(0,9223372036854775808n,true);
  else view.setFloat64(0,2.5,true);
  return bytes;
};
const taggedReader = (tag: number, payload: Uint8Array): DfmReader =>
  new DfmReader(Uint8Array.from([0,0,0,0,tag,...payload]));

// TValueType in FPC classesh.inc: preserve 64-bit values and x87 bytes exactly.
for (const [tag,kind,value] of [[2,"number","-1"],[3,"number","-2"],[4,"number","-3"],
  [5,"extended","00010203040506070809"],[15,"number","1.5"],[16,"number","10001 / 10000"],
  [17,"number","2.5"],[19,"number","-42"],[22,"number","9223372036854775808"],[23,"number","2.5"]] as const) {
  void test(`preserves binary form scalar type ${tag}`, () => {
    assert.deepEqual(readDfmValue(taggedReader(tag,numericPayload(tag))),{kind,value});
  });
}
void test("decodes all counted form string encodings and set terminators", () => {
  assert.deepEqual(readDfmValue(taggedReader(12,Uint8Array.of(1,0,0,0,233))),{kind:"string",value:"\u00e9"});
  assert.deepEqual(readDfmValue(taggedReader(18,Uint8Array.of(1,0,0,0,169,3))),{kind:"string",value:"\u03a9"});
  assert.deepEqual(readDfmValue(taggedReader(20,Uint8Array.of(2,0,0,0,195,169))),{kind:"string",value:"\u00e9"});
  assert.deepEqual(readDfmValue(taggedReader(21,Uint8Array.of(1,0,0,0,169,3))),{kind:"string",value:"\u03a9"});
  assert.deepEqual(readDfmValue(taggedReader(11,Uint8Array.of(3,79,110,101,0))),{kind:"set",values:["One"]});
  assert.deepEqual(readDfmValue(taggedReader(8,new Uint8Array())),{kind:"boolean",value:false});
  assert.deepEqual(readDfmValue(taggedReader(9,new Uint8Array())),{kind:"boolean",value:true});
  assert.deepEqual(readDfmValue(taggedReader(13,new Uint8Array())),{kind:"null"});
});
void test("rejects invalid reader locations, unsupported values and oversized string ranges", () => {
  const reader = new DfmReader(new Uint8Array(4));
  reader.offset = -1;
  assert.throws(()=>reader.peek(),/terminator/);
  assert.throws(()=>reader.read(1),/truncated/);
  assert.throws(()=>readDfmValue(taggedReader(99,new Uint8Array())),/unsupported/);
  assert.throws(()=>readDfmValue(taggedReader(18,Uint8Array.of(255,255,255,255))),/truncated/);
});
