import assert from "node:assert/strict";
import { test } from "node:test";
import { tokenizeRegistry } from "../../../../../../analyzers/pe/resources/preview/registry-tokens.js";

// NextToken's newLength + 1 < MAX_VALUE=4096 yields maximum 4094; 4095 must warn.
// https://github.com/adzm/atlmfc/blob/master/include/statreg.h (MAX_VALUE, NextToken)
// Counts 100000/100001 straddle the removed token cap; they are regression sizes, not ATL limits.
void test("ATL tokens preserve GUID braces, doubled apostrophes, paths and positions", () => {
  const issues: string[] = [];
  const tokens = tokenizeRegistry("HKCR\r\n{\n\t'O''Brien' = s 'C:\\server.dll' {GUID}\r}", issues);
  assert.deepEqual(tokens.map(token => token.text),
    ["HKCR", "{", "O'Brien", "=", "s", "C:\\server.dll", "{GUID}", "}"]);
  assert.deepEqual(tokens[2], { text: "O'Brien", quoted: true, line: 3, column: 2 });
  assert.deepEqual(tokens.at(-1), { text: "}", quoted: false, line: 4, column: 1 });
  assert.deepEqual(issues, []);
});

void test("unterminated strings include an escaped apostrophe at end of input", () => {
  const issues: string[] = [];
  assert.equal(tokenizeRegistry("'broken''", issues)[0]?.text, "broken'");
  assert.match(issues.join(" "), /unterminated/);
});

void test("token positions include same-line whitespace and newlines inside quoted text", () => {
  assert.deepEqual(tokenizeRegistry("One  Two = 'Three'", []).map(({ line, column }) => [line, column]),
    [[1, 1], [1, 6], [1, 10], [1, 12]]);
  assert.deepEqual(tokenizeRegistry("'first\nsecond' Last", [])[1],
    { text: "Last", quoted: false, line: 2, column: 9 });
  assert.deepEqual(tokenizeRegistry("\r\n\r\nWord", [])[0],
    { text: "Word", quoted: false, line: 3, column: 1 });
  assert.deepEqual(tokenizeRegistry("''next", []).map(token => token.text), ["", "next"]);
  assert.deepEqual(tokenizeRegistry("'a''b'next", []).map(token => token.text), ["a'b", "next"]);
  assert.deepEqual(tokenizeRegistry("One\n\n", []), [{ text: "One", quoted: false, line: 1, column: 1 }]);
  assert.deepEqual(tokenizeRegistry("First\r\nMiddle\nLast", [])[2],
    { text: "Last", quoted: false, line: 3, column: 1 });
  assert.deepEqual(tokenizeRegistry("'unfinished with several spaces", []).map(token => token.text),
    ["unfinished with several spaces"]);
});

void test("comment-like syntax is diagnosed only at the beginning of a token", () => {
  const issues: string[] = [];
  tokenizeRegistry("'https://example/path' 'a;b' 'a/*b'", issues);
  assert.deepEqual(issues, []);
  tokenizeRegistry("//comment", issues);
  assert.deepEqual(issues, ["ATL RGS 1:1: ATL does not support comments; token retained."]);
});

void test("empty and truncated tokens are retained with visible warnings", () => {
  const issues: string[] = [];
  assert.deepEqual(tokenizeRegistry("'' 'unfinished", issues).map(token => token.text), ["", "unfinished"]);
  assert.match(issues.join(" "), /unterminated/);
  assert.equal(tokenizeRegistry("", []).length, 0);
});

void test("comments and oversized ATL tokens are diagnosed without hiding data", () => {
  const issues: string[] = [];
  const large = "x".repeat(4095); // NextToken MAX_VALUE=4096 reserves two slots.
  assert.equal(tokenizeRegistry(`;comment //comment /*comment ${large}`, issues).length, 4);
  assert.equal(issues.length, 4);
  assert.match(issues.join(" "), /4K/);
});

void test("all tokens are retained regardless of token count", () => {
  const issues: string[] = [];
  assert.equal(tokenizeRegistry("Key ".repeat(100001), issues).length, 100001);
  assert.deepEqual(issues, []);
});

void test("exact token and ATL character limits do not mark complete input as partial", () => {
  const issues: string[] = [];
  assert.equal(tokenizeRegistry("Key ".repeat(100000), issues).length, 100000);
  assert.equal(tokenizeRegistry("x".repeat(4094), issues)[0]?.text.length, 4094);
  assert.deepEqual(issues, []);
});
