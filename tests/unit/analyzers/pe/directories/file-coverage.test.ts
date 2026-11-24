import assert from "node:assert/strict";
import { test } from "node:test";
import { peDirectoryCoverageIssue } from "../../../../../analyzers/pe/directories/file-coverage.js";
import { createBasePe } from "../../../../fixtures/pe-renderer-headers-fixture.js";

void test("PE directory coverage checks the full file-backed RVA span", () => {
  const pe = createBasePe();
  pe.rvaToOff = rva => rva >= 10 && rva < 14 ? rva - 10 : null;
  assert.equal(peDirectoryCoverageIssue({ name: "IMPORT", rva: 10, size: 4 }, pe), null);
  assert.match(peDirectoryCoverageIssue({ name: "IMPORT", rva: 10, size: 5 }, pe) ?? "",
    /partly backed/);
  assert.match(peDirectoryCoverageIssue({ name: "EXPORT", rva: 15, size: 4 }, pe) ?? "",
    /does not map/);
  assert.match(peDirectoryCoverageIssue({ name: "RESOURCE", rva: 0, size: 4 }, pe) ?? "",
    /RVA is zero/);
  assert.match(peDirectoryCoverageIssue({ name: "RESOURCE", rva: 15, size: 0 }, pe) ?? "",
    /size is zero/);
});

void test("PE directory coverage uses file offsets for SECURITY and a reserved size for GLOBALPTR",
  () => {
    const pe = createBasePe();
    assert.equal(peDirectoryCoverageIssue({
      name: "SECURITY", rva: pe.fileSize - 4, size: 4
    }, pe), null);
    assert.match(peDirectoryCoverageIssue({
      name: "SECURITY", rva: pe.fileSize - 4, size: 5
    }, pe) ?? "", /beyond the file/);
    assert.match(peDirectoryCoverageIssue({ name: "SECURITY", rva: 0, size: 4 }, pe) ?? "",
      /offset is zero/);
    assert.match(peDirectoryCoverageIssue({ name: "SECURITY", rva: pe.fileSize, size: 0 }, pe) ?? "",
      /size is zero/);
    assert.equal(peDirectoryCoverageIssue({ name: "GLOBALPTR", rva: 15, size: 0 }, pe), null);
  });
