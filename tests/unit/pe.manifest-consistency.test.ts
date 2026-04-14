"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  analyzeManifestConsistency,
  attachManifestValidation,
  collectManifestWarnings
} from "../../analyzers/pe/resources/manifest-consistency.js";
import {
  createClrHeaderFixture,
  createManifestResourcesFixture
} from "../fixtures/pe-manifest-preview-fixture.js";

// IMAGE_FILE_HEADER.Machine values are defined by the PE/COFF spec and winnt.h.
const AMD64_MACHINE = 0x8664;
const I386_MACHINE = 0x014c;
// This value is only used as a non-mapped synthetic machine for unhappy-path coverage.
const SYNTHETIC_UNMAPPED_MACHINE = 0x7ffe;
// COMIMAGE_FLAGS_ILONLY is defined by ECMA-335 II.25.3.3.1.
const CLR_ILONLY_FLAG = 0x00000001;

void test("collectManifestWarnings reports manifest processorArchitecture mismatches", () => {
  const subject = createManifestResourcesFixture([{
    processorArchitecture: "x86",
    requestedExecutionLevel: "asInvoker"
  }]);
  const warnings = collectManifestWarnings(
    subject.resources,
    AMD64_MACHINE,
    null
  );

  assert.ok(warnings.some(warning => /processorArchitecture="x86"/.test(warning)));
  assert.ok(warnings.some(warning => warning.includes(`ID ${subject.entries[0]?.resourceId}`)));
  assert.ok(warnings.some(warning => warning.includes(`LANG ${subject.entries[0]?.lang}`)));
  assert.ok(warnings.some(warning => /"amd64" or "\*"/.test(warning)));
});

void test("collectManifestWarnings requires IL-only CLR metadata for supportedArchitectures", () => {
  const subject = createManifestResourcesFixture([{
    processorArchitecture: "*",
    supportedArchitectures: ["amd64", "arm64"]
  }]);

  const withoutClr = collectManifestWarnings(subject.resources, I386_MACHINE, null);
  const withIlOnlyClr = collectManifestWarnings(
    subject.resources,
    I386_MACHINE,
    createClrHeaderFixture(CLR_ILONLY_FLAG)
  );

  assert.ok(withoutClr.some(warning => /supportedArchitectures/.test(warning)));
  assert.ok(!withIlOnlyClr.some(warning => /supportedArchitectures/.test(warning)));
});

void test("analyzeManifestConsistency returns validated checks when the manifest matches the image", () => {
  const subject = createManifestResourcesFixture([{
    processorArchitecture: "amd64",
    requestedExecutionLevel: "asInvoker"
  }]);
  const validation = analyzeManifestConsistency(
    subject.resources,
    AMD64_MACHINE,
    null
  );

  assert.equal(validation?.status, "consistent");
  assert.ok(validation?.validated.some(message => /processorArchitecture="amd64"/.test(message)));
  assert.ok(validation?.checkedCount);
  assert.deepEqual(validation?.warnings, []);
});

void test("collectManifestWarnings reports conflicting embedded manifest metadata", () => {
  const subject = createManifestResourcesFixture([
    {
      processorArchitecture: "amd64",
      requestedExecutionLevel: "asInvoker"
    },
    {
      processorArchitecture: "x86",
      requestedExecutionLevel: "requireAdministrator"
    }
  ]);
  const warnings = collectManifestWarnings(
    subject.resources,
    AMD64_MACHINE,
    null
  );

  assert.ok(warnings.some(warning => /disagree on processorArchitecture/i.test(warning)));
  assert.ok(warnings.some(warning => /disagree on requestedExecutionLevel/i.test(warning)));
});

void test("collectManifestWarnings formats neutral manifest entries and ignores unsupported machines", () => {
  const subject = createManifestResourcesFixture([{
    resourceId: null,
    lang: null,
    processorArchitecture: "amd64",
    supportedArchitectures: ["amd64"]
  }]);
  const warnings = collectManifestWarnings(
    subject.resources,
    SYNTHETIC_UNMAPPED_MACHINE,
    null
  );

  assert.equal(warnings.length, 1);
  assert.ok(warnings[0]);
  assert.match(warnings[0], /unnamed ID \/ LANG neutral/);
  assert.doesNotMatch(warnings[0], /COFF Machine/);
});

void test("collectManifestWarnings returns no warnings when manifest resources are absent", () => {
  assert.deepEqual(collectManifestWarnings(null, AMD64_MACHINE, null), []);
});

void test("attachManifestValidation annotates manifest resource previews", () => {
  const subject = createManifestResourcesFixture([{
    processorArchitecture: "amd64",
    requestedExecutionLevel: "asInvoker"
  }]);
  const validation = analyzeManifestConsistency(subject.resources, AMD64_MACHINE, null);
  const annotated = attachManifestValidation(subject.resources, validation);
  const manifestLang = annotated?.detail[0]?.entries[0]?.langs[0];

  assert.equal(manifestLang?.manifestValidation?.status, "consistent");
  assert.ok(manifestLang?.manifestValidation?.validated.length);
});
