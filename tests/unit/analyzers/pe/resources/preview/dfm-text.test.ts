import assert from "node:assert/strict";
import { test } from "node:test";
import { addTextDfmPreview } from "../../../../../../analyzers/pe/resources/preview/dfm-text.js";

void test("reads textual forms without executing named event handlers", () => {
  const result = addTextDfmPreview("object Main: TForm\n Caption = 'Don''t'#32'run'\n" +
    "OnCreate = FormCreate\n Anchors = [akLeft, akTop]\n" +
    "object Accept: TButton [0]\n Left = 12\n Caption = 'OK'\n end\nend");

  assert.equal(result?.preview?.dfm?.properties[0]?.value.kind, "string");
  assert.deepEqual(result?.preview?.dfm?.properties[0]?.value, { kind: "string", value: "Don't run" });
  assert.deepEqual(result?.preview?.dfm?.properties[1]?.value, { kind: "identifier", value: "FormCreate" });
  assert.equal(result?.preview?.dfm?.children[0]?.childPosition, "0");
  assert.equal(result?.issues, undefined);
});

void test("reads lists, collections, binary values and inherited forms", () => {
  const result = addTextDfmPreview("inherited Main: TForm\n Items.Strings = ('a' 'b')\n" +
    "Data = {00FF}\nColumns = <item Name = 'First' end>\nEnabled = True\nValue = $FF\nend");

  assert.equal(result?.preview?.dfm?.flags, 1);
  assert.deepEqual(result?.preview?.dfm?.properties[0]?.value,
    { kind: "list", values: [{ kind: "string", value: "a" }, { kind: "string", value: "b" }] });
  assert.equal(result?.preview?.dfm?.properties[2]?.value.kind, "collection");
  assert.equal(result?.issues, undefined);
});

void test("retains partial forms and rejects unrelated text", () => {
  const result = addTextDfmPreview("object Main: TForm\nCaption = 'open");

  assert.equal(result?.preview?.dfm?.name, "Main");
  assert.match(result?.issues?.join(" ") ?? "", /unterminated/);
  assert.equal(addTextDfmPreview("some ordinary text"), null);
  assert.ok(addTextDfmPreview("object Main: TForm")?.issues?.length);
});

void test("preserves inline components, booleans, nulls, decimal numbers and explicit concatenation", () => {
  const result = addTextDfmPreview("inline Main: TForm\nCaption = 'A' + #$42\nEnabled = False\n"+
    "Target = nil\nValue = -1.5e2\nItems = ()\nColumns = <>\nend trailing");
  assert.equal(result?.preview?.dfm?.flags,4);
  assert.deepEqual(result?.preview?.dfm?.properties.map(item=>item.value),[
    {kind:"string",value:"AB"},{kind:"boolean",value:false},{kind:"null"},{kind:"number",value:"-1.5e2"},
    {kind:"list",values:[]},{kind:"collection",items:[]}
  ]);
  assert.match(result?.issues?.join(" ") ?? "",/after its root/);
});
for (const value of ["'open\n", "'text' + end", "#1114112", "[ 'bad' ]", "{ABC}", "{GG}", "<unknown>", "@bad"]) {
  void test(`reports malformed form property ${JSON.stringify(value)}`, () => {
    assert.ok(addTextDfmPreview("object Main: TForm\nValue = "+value+"\nend")?.issues?.length);
  });
}
