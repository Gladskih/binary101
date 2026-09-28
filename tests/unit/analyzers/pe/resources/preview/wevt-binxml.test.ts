import assert from "node:assert/strict";
import { test } from "node:test";
import { parseWevtBinXml } from "../../../../../../analyzers/pe/resources/preview/wevt-binxml.js";

// MS-EVEN6 §2.2.12: fragment header, open A, inline NameHash 0x41, substitution, end.
const fragment = (): Uint8Array => Uint8Array.from([
  0x0f, 1, 1, 0,
  0x01, 0xff, 0xff, 14, 0, 0, 0,
  0x41, 0, 1, 0, 0x41, 0, 0, 0,
  0x02, 0x0d, 0, 0, 7, 0x04, 0
]);

void test("decodes an inline-name XML element with a substitution", () => {
  const bytes = fragment();
  const issues: string[] = [];
  assert.deepEqual(parseWevtBinXml(bytes, 0, bytes.length, issues), {
    name: "A", attributes: [], text: "{sub:0}", children: []
  });
  assert.deepEqual(issues, []);
});

void test("warns on a damaged inline-name hash", () => {
  const bytes = fragment();
  bytes[11] = 0;
  const issues: string[] = [];
  assert.equal(parseWevtBinXml(bytes, 0, bytes.length, issues), null);
  assert.ok(issues.some(issue => /hash/.test(issue)));
});

void test("bounds checks an incomplete fragment and public offsets", () => {
  const bytes = fragment();
  const truncated: string[] = [];
  assert.equal(parseWevtBinXml(bytes, 0, 16, truncated), null);
  assert.ok(truncated.length);
  const invalid: string[] = [];
  assert.equal(parseWevtBinXml(bytes, -1, bytes.length, invalid), null);
  assert.ok(invalid.length);
});

const inlineName = (label: string): number[] => {
  // MS-EVEN6 2.2.12.9 NameHash multiplies the rolling hash by 65599.
  const hash = [...label].reduce((current, char) =>
    (Math.imul(current, 65599) + char.charCodeAt(0)) & 0xffff, 0);
  return [hash & 0xff, hash >> 8, label.length, 0,
    ...[...label].flatMap(char => [char.charCodeAt(0), 0]), 0, 0];
};

const xmlElement = (label: string, content: number[] = [], attrs: number[] = []): number[] => {
  const body = [...inlineName(label), ...(attrs.length ?
    [attrs.length & 0xff, attrs.length >> 8, 0, 0, ...attrs] : []),
  content.length ? 2 : 3, ...content, ...(content.length ? [4] : [])];
  return [attrs.length ? 0x41 : 1, 0xff, 0xff, body.length & 0xff,
    body.length >> 8 & 0xff, body.length >> 16 & 0xff, body.length >> 24 & 0xff, ...body];
};

const xmlFragment = (element: number[]): Uint8Array => Uint8Array.from([15, 1, 1, 0,
  ...element]);

const decode = (bytes: Uint8Array): { tree: ReturnType<typeof parseWevtBinXml>;
  issues: string[] } => {
  const issues: string[] = [];
  return { tree: parseWevtBinXml(bytes, 0, bytes.length, issues), issues };
};

void test("decodes nested elements, attributes and supported value tokens", () => {
  const attribute = [6, ...inlineName("id"), 0x0e, 2, 0, 7];
  const child = xmlElement("Child", [5, 1, 1, 0, 0x58, 0]);
  const bytes = xmlFragment(xmlElement("Root", [
    ...child, 7, 1, 0, 0x59, 0, 8, 0x3c, 0, 9, ...inlineName("amp")
  ], attribute));
  assert.deepEqual(decode(bytes), { tree: {
    name: "Root", attributes: [{ name: "id", value: "{sub:2}" }],
    text: "Y<&amp;", children: [{ name: "Child", attributes: [], text: "X", children: [] }]
  }, issues: [] });
});

void test("accepts an empty attribute list and an optional substitution", () => {
  const bytes = xmlFragment(xmlElement("A", [0x0e, 3, 0, 1], [
    6, ...inlineName("x"), 5, 1, 1, 0, 0x56, 0
  ]));
  assert.deepEqual(decode(bytes), { tree: { name: "A", attributes: [{ name: "x", value: "V" }],
    text: "{sub:3}", children: [] }, issues: [] });
});

void test("rejects invalid public ranges and fragment headers", () => {
  const bytes = xmlFragment(xmlElement("A"));
  for (const range of [[0.5, bytes.length], [0, bytes.length + 1],
    [bytes.length, bytes.length], [0, 3]] as Array<[number, number]>) {
    const issues: string[] = [];
    assert.equal(parseWevtBinXml(bytes, range[0], range[1], issues), null);
    assert.ok(issues.length);
  }
  for (const index of [0, 1, 2, 3]) {
    const damaged = bytes.slice();
    damaged[index] = (damaged[index] ?? 0) ^ 0xff;
    assert.equal(decode(damaged).tree, null);
  }
});

void test("checks element, name and closing delimiters", () => {
  const valid = xmlFragment(xmlElement("A"));
  for (const [index, replacement] of [[4, 0], [11, 0xff], [12, 0xff],
    [15, 0xff], [17, 1], [19, 0]] as Array<[number, number]>) {
    const damaged = valid.slice();
    damaged[index] = replacement;
    assert.equal(decode(damaged).tree, null, `byte ${index}`);
    assert.ok(decode(damaged).issues.length);
  }
});

void test("reports unsupported and truncated value tokens", () => {
  const valid = xmlFragment(xmlElement("A", [0x0d, 0, 0, 1]));
  for (const token of [0x40, 5, 8, 9]) {
    const damaged = valid.slice();
    damaged[20] = token;
    assert.equal(decode(damaged).tree, null);
    assert.ok(decode(damaged).issues.length);
  }
  const badText = xmlFragment(xmlElement("A", [5, 2, 0, 0]));
  assert.equal(decode(badText).tree, null);
});

void test("checks attribute list length and token", () => {
  const valid = xmlFragment(xmlElement("A", [], [6, ...inlineName("x"), 7, 1, 0, 0x56, 0]));
  for (const [index, replacement] of [[20, 0xff], [24, 0], [25, 0xff]] as Array<
    [number, number]>) {
    const damaged = valid.slice();
    damaged[index] = replacement;
    assert.equal(decode(damaged).tree, null, `byte ${index}`);
  }
});

void test("decodes normal and flagged text, character and entity tokens", () => {
  const body = [0x45, 1, 1, 0, 0x41, 0, 0x47, 1, 0, 0x42, 0,
    0x48, 0x3c, 0, 0x49, ...inlineName("amp")];
  assert.deepEqual(decode(xmlFragment(xmlElement("A", body))), {
    tree: { name: "A", attributes: [], text: "AB<&amp;", children: [] }, issues: []
  });
});

void test("reports malformed text, char reference, entity and substitution payloads", () => {
  const cases = [
    [5, 2, 0, 0], [5, 1, 2, 0, 0], [7, 2, 0, 0], [8, 1],
    [9, 0, 0, 1, 0, 0x41, 0, 0, 0], [0x0d, 0], [0x0e, 0, 0]
  ];
  for (const content of cases) {
    const result = decode(xmlFragment(xmlElement("A", content)));
    assert.equal(result.tree, null);
    assert.ok(result.issues.length);
  }
});

void test("rejects malformed names, element lengths and end markers", () => {
  const valid = xmlFragment(xmlElement("A", [0x0d, 0, 0, 1]));
  const changes: Array<[number, number]> = [
    [8, 0xff], // Element size extends beyond the fragment.
    [14, 0xff], // Inline-name UTF-16 length extends beyond the fragment.
    [18, 1], // Inline-name terminator must be NUL.
    [19, 3], // A nonempty element cannot use a self-closing token.
    [24, 5] // The element must end with EndElement (0x04).
  ];
  for (const [index, replacement] of changes) {
    const damaged = valid.slice();
    damaged[index] = replacement;
    assert.equal(decode(damaged).tree, null, `byte ${index}`);
  }
});

void test("rejects a damaged attribute value or list size", () => {
  const valid = xmlFragment(xmlElement("A", [], [6, ...inlineName("x"), 5, 1, 1, 0,
    0x56, 0]));
  const changes: Array<[number, number]> = [[20, 0xff], [24, 0], [25, 0xff],
    [34, 2]];
  for (const [index, replacement] of changes) {
    const damaged = valid.slice();
    damaged[index] = replacement;
    assert.equal(decode(damaged).tree, null, `byte ${index}`);
  }
});

void test("stops nested XML at the documented depth limit", () => {
  let nested = xmlElement("Z");
  for (let index = 0; index < 33; index += 1) nested = xmlElement("N", nested);
  const result = decode(xmlFragment(nested));
  assert.equal(result.tree, null);
  assert.deepEqual(result.issues, ["WEVT BinXML nesting is too deep."]);
});

void test("accepts the maximum nesting depth", () => {
  let nested = xmlElement("Z");
  for (let index = 0; index < 32; index += 1) nested = xmlElement("N", nested);
  const result = decode(xmlFragment(nested));
  assert.equal(result.tree?.name, "N");
  assert.deepEqual(result.issues, []);
});

void test("reads multiple flagged and unflagged attributes", () => {
  const attrs = [6, ...inlineName("a"), 7, 1, 0, 0x41, 0,
    0x46, ...inlineName("b"), 0x0d, 2, 0, 1];
  assert.deepEqual(decode(xmlFragment(xmlElement("A", [], attrs))), {
    tree: { name: "A", attributes: [{ name: "a", value: "A" },
      { name: "b", value: "{sub:2}" }], text: null, children: [] }, issues: []
  });
});

void test("reports precise structural errors", () => {
  const valid = xmlFragment(xmlElement("A", [0x0d, 0, 0, 1]));
  const cases: Array<[number, number, string]> = [
    [4, 0, "WEVT BinXML element token is invalid."],
    [7, 0xff, "WEVT BinXML element is truncated."],
    [11, 0, "WEVT BinXML inline name has an invalid NUL or hash."],
    [19, 0, "WEVT BinXML start tag is not closed."],
    [20, 0x40, "WEVT BinXML token 0x40 is unsupported."],
    [19, 3, "WEVT BinXML element end is invalid."]
  ];
  for (const [index, replacement, message] of cases) {
    const damaged = valid.slice();
    damaged[index] = replacement;
    assert.deepEqual(decode(damaged), { tree: null, issues: [message] });
  }
});

void test("reports precise attribute errors", () => {
  const valid = xmlFragment(xmlElement("A", [], [6, ...inlineName("x"),
    7, 1, 0, 0x56, 0]));
  const cases: Array<[number, number, string]> = [
    [20, 0xff, "WEVT BinXML attribute list is truncated."],
    [23, 0, "WEVT BinXML attribute token is invalid."],
    [24, 0, "WEVT BinXML inline name has an invalid NUL or hash."]
  ];
  for (const [index, replacement, message] of cases) {
    const damaged = valid.slice();
    damaged[index] = replacement;
    assert.deepEqual(decode(damaged), { tree: null, issues: [message] });
  }
});

void test("reports invalid public ranges and fragment bytes precisely", () => {
  const valid = xmlFragment(xmlElement("A"));
  const ranges: Array<[number, number]> = [[Number.NaN, valid.length],
    [0, Number.NaN], [0, valid.length + 1], [0, 3], [1, 0]];
  for (const [start, end] of ranges) {
    const issues: string[] = [];
    assert.equal(parseWevtBinXml(valid, start, end, issues), null);
    assert.deepEqual(issues, ["WEVT BinXML range is invalid or truncated."]);
  }
  for (const index of [0, 1, 2, 3]) {
    const damaged = valid.slice();
    damaged[index] = 0xff;
    assert.deepEqual(decode(damaged), { tree: null,
      issues: ["WEVT BinXML fragment header is invalid."] });
  }
});
