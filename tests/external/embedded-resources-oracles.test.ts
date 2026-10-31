import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { decodeRcc } from "../../analyzers/embedded-resources/rcc.js";
import { decodeGResource } from "../../analyzers/embedded-resources/gresource.js";
import { readEmbeddedResourceContent } from "../../analyzers/embedded-resources/content.js";
import { resolveResourcePayload } from "../../analyzers/embedded-resources/payload.js";
import { parseElf } from "../../analyzers/elf/index.js";
import { parsePe } from "../../analyzers/pe/index.js";
import { MockFile } from "../helpers/mock-file.js";

const oracleFile = (name: string): MockFile => new MockFile(new Uint8Array(readFileSync(
  new URL(`../../generated/embedded-resource-oracles/${name}`, import.meta.url))));

for (const name of ["oracle-v1.rcc", "oracle-v2.rcc", "oracle-v3.rcc", "oracle.gresource"]) {
  void test(`extracts genuine upstream ${name}`, async () => {
    const file = oracleFile(name);
    const result = await (name.endsWith("rcc") ? decodeRcc : decodeGResource)(file, 0, file.size);
    assert.deepEqual(result.issues, []);
    assert.ok(result.value);
    const message = result.value.entries.find(entry => entry.name === "message.txt");
    assert.ok(message);
    const payload = resolveResourcePayload(result.value.format, message);
    assert.ok(payload);
    const content = await readEmbeddedResourceContent(file, payload, 2000);
    assert.deepEqual(content.issues, []);
    assert.equal(new TextDecoder().decode(content.value!), "Binary101 resource oracle ".repeat(50));
  });
}

for (const [name, count] of [["qt-glib.so", 4], ["qt-glib.dll", 4], ["qt-arrays.o", 1]] as const) {
  void test(`finds confirmed resources in genuine upstream ${name}`, async () => {
    const file = oracleFile(name);
    const parsed = await (name.endsWith("dll") ? parsePe(file) : parseElf(file));
    assert.equal(parsed?.embeddedResources?.bundles.length, count);
    assert.deepEqual(parsed?.embeddedResources?.issues, []);
  });
}
