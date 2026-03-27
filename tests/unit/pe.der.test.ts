"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeOid, parseDerTime, readDerElement } from "../../analyzers/pe/der.js";

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

void test("readDerElement rejects non-minimal long-form lengths in DER", () => {
  // ITU-T X.690 DER requires the length to use the fewest possible octets.
  // Length 1 must use the short form, not 0x81 0x01.
  const element = readDerElement(Uint8Array.of(0x04, 0x81, 0x01, 0x00), 0);
  assert.strictEqual(element, null);
});

void test("decodeOid rejects non-minimal base-128 encodings in DER", () => {
  // ITU-T X.690 DER requires each subidentifier to use the fewest possible octets.
  assert.strictEqual(decodeOid(Uint8Array.of(0x2a, 0x80, 0x03), 0, 3), null);
});

void test(
  "parseDerTime does not invent missing seconds for X.509 UTCTime or GeneralizedTime",
  () => {
  const encoder = new TextEncoder();
  // RFC 5280 sections 4.1.2.5.1 and 4.1.2.5.2 require seconds in both UTCTime and GeneralizedTime.
  const utcRaw = encoder.encode("2401010000Z");
  const utcBytes = new Uint8Array(utcRaw.length + 2);
  utcBytes[0] = 0x17;
  utcBytes[1] = utcRaw.length;
  utcBytes.set(utcRaw, 2);
  const utcElement = readDerElement(utcBytes, 0);
  assert.ok(utcElement);
  assert.strictEqual(parseDerTime(utcBytes, utcElement), "2401010000Z");

  const generalizedRaw = encoder.encode("202401010000Z");
  const generalizedBytes = new Uint8Array(generalizedRaw.length + 2);
  generalizedBytes[0] = 0x18;
  generalizedBytes[1] = generalizedRaw.length;
  generalizedBytes.set(generalizedRaw, 2);
  const generalizedElement = readDerElement(generalizedBytes, 0);
  assert.ok(generalizedElement);
  assert.strictEqual(parseDerTime(generalizedBytes, generalizedElement), "202401010000Z");
  }
);
