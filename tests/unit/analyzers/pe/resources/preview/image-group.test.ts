import assert from "node:assert/strict";
import { test } from "node:test";
import { addImageGroupPreview } from "../../../../../../analyzers/pe/resources/preview/image-group.js";
import { buildSingleEntryGroupCursorResource, buildSingleEntryGroupIconResource } from
  "../../../../../helpers/pe-resource-preview-fixture.js";
import { assertResourcePrefixWarnings } from "../../../../../helpers/resource-prefix-warnings.js";
import { expectDefined } from "../../../../../helpers/expect-defined.js";

void test("reads cursor WORD dimensions separately from planes and bit count", () => {
  const bytes = buildSingleEntryGroupCursorResource(70, 80, 1, 32);
  const view = new DataView(bytes.buffer);
  view.setUint16(6, 300, true); view.setUint16(8, 600, true);
  const group = expectDefined(addImageGroupPreview(bytes, "GROUP_CURSOR")?.preview?.imageGroup);

  assert.deepEqual(group, { type: "CURSOR", entries: [
    { id: 80, width: 300, height: 600, planes: 1, bitCount: 32, size: 70 }
  ] });
});

void test("reads icon zero dimensions as 256 and reports all truncated prefixes", () => {
  const bytes = buildSingleEntryGroupIconResource(70, 80);
  bytes[6] = 0; bytes[7] = 0;
  const group = expectDefined(addImageGroupPreview(bytes, "GROUP_ICON")?.preview?.imageGroup);

  assert.equal(group.entries[0]?.width, 256);
  assert.equal(group.entries[0]?.height, 256);
  assertResourcePrefixWarnings(bytes, prefix => addImageGroupPreview(prefix, "GROUP_ICON"));
  assert.equal(addImageGroupPreview(bytes, "OTHER"), null);
});

void test("reports trailing group bytes instead of silently ignoring them", () => {
  const bytes = Uint8Array.from([...buildSingleEntryGroupIconResource(70, 80), 1]);

  assert.match(addImageGroupPreview(bytes, "GROUP_ICON")?.issues?.join(" ") ?? "", /trailing/);
});

void test("preserves an invalid zero WORD cursor dimension instead of treating it as an icon byte", () => {
  const bytes = new Uint8Array(20);
  const view = new DataView(bytes.buffer);
  view.setUint16(2, 2, true); view.setUint16(4, 1, true);
  view.setUint16(8, 32, true);

  const result = addImageGroupPreview(bytes, "GROUP_CURSOR");

  assert.equal(result?.preview?.imageGroup?.entries[0]?.width, 0);
  assert.match(result?.issues?.join(" ") ?? "", /dimension/);
});

const twoImageGroup = (type: number): Uint8Array => {
  const bytes = new Uint8Array(34);
  const view = new DataView(bytes.buffer);
  view.setUint16(2,type,true); view.setUint16(4,2,true);
  view.setUint16(6,256,true); view.setUint16(8,512,true);
  view.setUint16(10,1,true); view.setUint16(12,32,true); view.setUint32(14,123,true); view.setUint16(18,7,true);
  bytes[20]=16; bytes[21]=32; view.setUint16(22,64,true);
  view.setUint16(24,2,true); view.setUint16(26,8,true); view.setUint32(28,456,true); view.setUint16(32,9,true);
  return bytes;
};
void test("reads both entries and distinguishes BYTE icon dimensions from WORD cursor dimensions", () => {
  const cursor = addImageGroupPreview(twoImageGroup(2),"GROUP_CURSOR");
  const icon = addImageGroupPreview(twoImageGroup(1),"GROUP_ICON");

  assert.equal(cursor?.issues,undefined);
  assert.equal(icon?.issues,undefined);
  assert.deepEqual(cursor?.preview?.imageGroup?.entries,[
    {id:7,width:256,height:512,planes:1,bitCount:32,size:123},
    {id:9,width:8208,height:64,planes:2,bitCount:8,size:456}
  ]);
  assert.deepEqual(icon?.preview?.imageGroup?.entries,[
    {id:7,width:256,height:1,planes:1,bitCount:32,size:123},
    {id:9,width:16,height:32,planes:2,bitCount:8,size:456}
  ]);
});
void test("diagnoses reserved fields, mismatching types and empty directories independently", () => {
  const reserved = twoImageGroup(1);
  reserved[0]=1;
  const empty = Uint8Array.of(0,0,1,0,0,0);

  assert.match(addImageGroupPreview(reserved,"GROUP_ICON")?.issues?.join(" ") ?? "",/reserved/);
  assert.match(addImageGroupPreview(twoImageGroup(2),"GROUP_ICON")?.issues?.join(" ") ?? "",/resource type/);
  assert.match(addImageGroupPreview(empty,"GROUP_ICON")?.issues?.join(" ") ?? "",/no entries/);
  assert.equal(addImageGroupPreview(new Uint8Array(),"OTHER"),null);
  assert.match(addImageGroupPreview(new Uint8Array(5),"GROUP_ICON")?.issues?.join(" ") ?? "",/header/);
});

void test("reports a zero dimension even when another cursor entry is valid", () => {
  const bytes = twoImageGroup(2);
  new DataView(bytes.buffer).setUint16(8,0,true);
  assert.match(addImageGroupPreview(bytes,"GROUP_CURSOR")?.issues?.join(" ") ?? "",/dimension/);
});
