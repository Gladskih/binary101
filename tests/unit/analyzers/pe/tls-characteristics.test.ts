"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  formatTlsCharacteristicsReservedBits,
  isKnownTlsCharacteristicsAlignment,
  tlsCharacteristicsAlignmentBits,
  tlsCharacteristicsReservedBits
} from "../../../../analyzers/pe/tls-characteristics.js";

void test("TLS Characteristics decoder reports alignment bits and reserved bits separately", () => {
  // Microsoft PE format, "The TLS Directory": Characteristics uses bits [23:20]
  // for IMAGE_SCN_ALIGN_* and reserves the other 28 bits.
  const characteristics = 0x00500001;
  assert.equal(tlsCharacteristicsAlignmentBits(characteristics), 0x00500000);
  assert.equal(tlsCharacteristicsReservedBits(characteristics), 0x00000001);
  assert.equal(formatTlsCharacteristicsReservedBits(characteristics), "0x00000001");
});

void test("TLS Characteristics decoder accepts absent alignment and rejects unknown alignment", () => {
  assert.equal(isKnownTlsCharacteristicsAlignment(0), true);
  assert.equal(isKnownTlsCharacteristicsAlignment(0x00f00000), false);
});
