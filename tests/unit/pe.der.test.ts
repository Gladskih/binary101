"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeOid, readDerElement } from "../../analyzers/pe/der.js";

void test("readDerElement accepts valid long-form lengths that require four subsequent octets", () => {
  // ITU-T X.690 8.1.3.5 allows one or more subsequent length octets.
  // 0x01000000 is the smallest content length that requires four octets in the definite form.
  const contentLength = 0x01000000;
  const bytes = new Uint8Array(contentLength + 6);
  bytes[0] = 0x04;
  bytes[1] = 0x84;
  bytes[2] = 0x01;
  bytes[3] = 0x00;
  bytes[4] = 0x00;
  bytes[5] = 0x00;

  const element = readDerElement(bytes, 0);

  assert.ok(element);
  assert.strictEqual(element.length, contentLength);
  assert.strictEqual(element.header, 6);
  assert.strictEqual(element.end, bytes.length);
});

void test("decodeOid decodes a first subidentifier that spans multiple octets", () => {
  // ITU-T X.690 8.19.4 example: { 2 100 3 } encodes to contents 81 34 03.
  assert.strictEqual(decodeOid(Uint8Array.of(0x81, 0x34, 0x03), 0, 3), "2.100.3");
});
