"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseVcFeatureInfo } from "../../analyzers/pe/debug/vc-feature.js";
import {
  createOffsetPayloadSubject,
  createTruncatedVcFeaturePayload,
  createVcFeatureSubjectCounters,
  createVcFeatureSubjectInfo,
  createVcFeaturePayload
} from "../fixtures/pe-debug-payload-subject.js";

const identityRvaToOff = (value: number): number => value;

void test("parseVcFeatureInfo reads the five VC_FEATURE counters", async () => {
  const warnings: string[] = [];
  const counters = createVcFeatureSubjectCounters();
  const { file, offset } = createOffsetPayloadSubject(createVcFeaturePayload(counters));

  const result = await parseVcFeatureInfo(
    file,
    file.size,
    identityRvaToOff,
    0,
    offset,
    file.size - offset,
    message => warnings.push(message)
  );

  assert.deepEqual(result, createVcFeatureSubjectInfo(counters));
  assert.deepEqual(warnings, []);
});

void test("parseVcFeatureInfo warns on truncated payloads", async () => {
  const warnings: string[] = [];
  const { file, offset } = createOffsetPayloadSubject(createTruncatedVcFeaturePayload());

  const result = await parseVcFeatureInfo(
    file,
    file.size,
    identityRvaToOff,
    0,
    offset,
    file.size - offset,
    message => warnings.push(message)
  );

  assert.equal(result, null);
  assert.match(warnings.join(" | "), /VC_FEATURE|truncated|smaller/i);
});
