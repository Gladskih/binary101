"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { collectPeLayoutWarnings } from "../../analyzers/pe/layout-warnings.js";
import {
  createDebugSection,
  createHeaderOnlyLayoutSubject,
  createIndexedSection,
  createMappedDebugEntry,
  createUnmappedDebugEntry,
  createWindowsLayoutSubject,
  DEFAULT_FILE_ALIGNMENT,
  DEFAULT_PE_HEADER_OFFSET,
  DEFAULT_SECTION_ALIGNMENT,
  getDeclaredHeaderSpan,
  getHeaderSpanSmallerThanDeclared,
  getSectionRawEnd,
  IMAGE_SCN_CNT_UNINITIALIZED_DATA
} from "../fixtures/pe-layout-warning-subject.js";
void test("collectPeLayoutWarnings returns no warnings for a canonical adjacent PE32 layout", () => {
  const warnings = collectPeLayoutWarnings(
    createWindowsLayoutSubject(
      createIndexedSection(0, DEFAULT_SECTION_ALIGNMENT, DEFAULT_FILE_ALIGNMENT),
      createIndexedSection(1, DEFAULT_SECTION_ALIGNMENT * 2, DEFAULT_FILE_ALIGNMENT * 2)
    )
  );
  assert.deepStrictEqual(warnings, []);
});
void test("collectPeLayoutWarnings reports header-only PE header alignment anomalies", () => {
  const warnings = collectPeLayoutWarnings(
    // PE headers are expected to be 8-byte aligned.
    createHeaderOnlyLayoutSubject(
      DEFAULT_PE_HEADER_OFFSET + 2,
      createIndexedSection(0, DEFAULT_SECTION_ALIGNMENT, 0)
    )
  );
  assert.ok(warnings.some(warning => /e_lfanew .* is not 8-byte aligned/i.test(warning)));
});
void test("collectPeLayoutWarnings reports header span and raw alignment anomalies", () => {
  const pe = createWindowsLayoutSubject(
    createIndexedSection(
      0,
      DEFAULT_SECTION_ALIGNMENT,
      getHeaderSpanSmallerThanDeclared(1),
      DEFAULT_FILE_ALIGNMENT,
      getHeaderSpanSmallerThanDeclared(1)
    )
  );
  // Make SizeOfHeaders both smaller than the declared section-table span and misaligned to FileAlignment.
  pe.opt.SizeOfHeaders = getHeaderSpanSmallerThanDeclared(1);
  const warnings = collectPeLayoutWarnings(pe);
  assert.ok(warnings.some(warning => /SizeOfHeaders .*smaller than the actual header span/i.test(warning)));
  assert.ok(warnings.some(warning => /SizeOfHeaders .*not a multiple of FileAlignment/i.test(warning)));
  assert.ok(warnings.some(warning => /PointerToRawData .*not a multiple of FileAlignment/i.test(warning)));
  assert.ok(warnings.some(warning => /SizeOfRawData .*not a multiple of FileAlignment/i.test(warning)));
  assert.ok(warnings.some(warning => /overlaps the headers ending/i.test(warning)));
});
void test("collectPeLayoutWarnings reports virtual layout ordering, overlap, and adjacency issues", () => {
  const warnings = collectPeLayoutWarnings(
    createWindowsLayoutSubject(
      createIndexedSection(0, DEFAULT_SECTION_ALIGNMENT * 3, DEFAULT_FILE_ALIGNMENT * 3),
      createIndexedSection(
        1,
        DEFAULT_SECTION_ALIGNMENT,
        DEFAULT_FILE_ALIGNMENT,
        DEFAULT_SECTION_ALIGNMENT
      ),
      createIndexedSection(
        2,
        DEFAULT_SECTION_ALIGNMENT + (DEFAULT_SECTION_ALIGNMENT >>> 1),
        DEFAULT_FILE_ALIGNMENT * 2,
        DEFAULT_FILE_ALIGNMENT >>> 1
      )
    )
  );
  assert.ok(warnings.some(warning => /not a multiple of SectionAlignment/i.test(warning)));
  assert.ok(warnings.some(warning => /not in ascending VirtualAddress order/i.test(warning)));
  assert.ok(warnings.some(warning => /overlap in the loaded image RVA layout/i.test(warning)));
  assert.ok(warnings.some(warning => /not adjacent in RVA order/i.test(warning)));
});
void test("collectPeLayoutWarnings reports raw layout order and overlap issues", () => {
  const warnings = collectPeLayoutWarnings(
    createWindowsLayoutSubject(
      createIndexedSection(0, DEFAULT_SECTION_ALIGNMENT, DEFAULT_FILE_ALIGNMENT * 3),
      createIndexedSection(
        1,
        DEFAULT_SECTION_ALIGNMENT * 2,
        DEFAULT_FILE_ALIGNMENT * 2 + (DEFAULT_FILE_ALIGNMENT >>> 1)
      )
    )
  );
  assert.ok(warnings.some(warning => /raw data is not ordered by RVA/i.test(warning)));
  assert.ok(warnings.some(warning => /overlap in file data/i.test(warning)));
});
void test("collectPeLayoutWarnings reports sub-page section alignment layout mismatches", () => {
  const pe = createWindowsLayoutSubject(
    createIndexedSection(
      0,
      DEFAULT_FILE_ALIGNMENT,
      DEFAULT_FILE_ALIGNMENT * 2,
      DEFAULT_FILE_ALIGNMENT * 2,
      DEFAULT_FILE_ALIGNMENT * 2
    )
  );
  pe.opt.SectionAlignment = DEFAULT_FILE_ALIGNMENT;
  pe.opt.FileAlignment = DEFAULT_FILE_ALIGNMENT * 2;
  const warnings = collectPeLayoutWarnings(pe);
  assert.ok(warnings.some(warning => /FileAlignment .*must match SectionAlignment/i.test(warning)));
  assert.ok(warnings.some(warning => /raw data offset .*must match its VirtualAddress/i.test(warning)));
});
void test("collectPeLayoutWarnings reports raw bytes in uninitialized-only sections", () => {
  const warnings = collectPeLayoutWarnings(
    createWindowsLayoutSubject(
      createIndexedSection(
        0,
        DEFAULT_SECTION_ALIGNMENT * 2,
        DEFAULT_FILE_ALIGNMENT,
        DEFAULT_FILE_ALIGNMENT,
        DEFAULT_FILE_ALIGNMENT,
        IMAGE_SCN_CNT_UNINITIALIZED_DATA
      )
    )
  );
  assert.ok(warnings.some(warning => /contains only uninitialized data.*SizeOfRawData/i.test(warning)));
  assert.ok(warnings.some(warning => /contains only uninitialized data.*PointerToRawData/i.test(warning)));
});
void test("collectPeLayoutWarnings uses declared NumberOfSections for the header span check", () => {
  const pe = createWindowsLayoutSubject(
    createIndexedSection(0, DEFAULT_SECTION_ALIGNMENT, DEFAULT_FILE_ALIGNMENT)
  );
  pe.coff.NumberOfSections = 2;
  pe.opt.SizeOfHeaders = getDeclaredHeaderSpan(1);
  const warnings = collectPeLayoutWarnings(pe);
  assert.ok(warnings.some(warning => /SizeOfHeaders .*smaller than the actual header span/i.test(warning)));
});

void test("collectPeLayoutWarnings reports security and debug tail anomalies", () => {
  const pe = createWindowsLayoutSubject(
    createIndexedSection(0, DEFAULT_SECTION_ALIGNMENT, DEFAULT_FILE_ALIGNMENT)
  );
  pe.overlaySize = DEFAULT_FILE_ALIGNMENT >>> 2;
  const securitySize = DEFAULT_FILE_ALIGNMENT >>> 3;
  const mappedImageEnd = getSectionRawEnd(pe.sections[0]!);
  // The certificate table is pushed back into the mapped image and the debug payload starts before it ends.
  pe.dirs = [{ name: "SECURITY", rva: mappedImageEnd - (securitySize >>> 1), size: securitySize }];
  pe.debug = createDebugSection(
    createUnmappedDebugEntry(
      mappedImageEnd - (securitySize >>> 3),
      pe.overlaySize - (securitySize >>> 2)
    )
  );

  const warnings = collectPeLayoutWarnings(pe);

  assert.ok(warnings.some(warning => /certificate table starts .*overlaps mapped image/i.test(warning)));
  assert.ok(warnings.some(warning => /debug raw data begins .*overlaps mapped image/i.test(warning)));
  assert.ok(warnings.some(warning => /certificate table and debug raw data overlap/i.test(warning)));
  assert.ok(warnings.some(warning => /does not immediately precede debug raw data/i.test(warning)));
  assert.ok(warnings.some(warning => /not placed at the end of the file tail/i.test(warning)));
});

void test("collectPeLayoutWarnings requires a certificate-only tail to reach EOF", () => {
  const pe = createWindowsLayoutSubject(
    createIndexedSection(0, DEFAULT_SECTION_ALIGNMENT, DEFAULT_FILE_ALIGNMENT)
  );
  const fileSize = getSectionRawEnd(pe.sections[0]!) + DEFAULT_FILE_ALIGNMENT;
  pe.dirs = [{
    name: "SECURITY",
    rva: getSectionRawEnd(pe.sections[0]!),
    size: DEFAULT_FILE_ALIGNMENT >>> 1
  }];

  const warnings = collectPeLayoutWarnings(pe, fileSize);

  assert.ok(warnings.some(warning => /certificate table .*not placed at the end of the file tail/i.test(warning)));
});

void test("collectPeLayoutWarnings reports gaps between debug raw ranges in the file tail", () => {
  const pe = createWindowsLayoutSubject(
    createIndexedSection(0, DEFAULT_SECTION_ALIGNMENT, DEFAULT_FILE_ALIGNMENT)
  );
  const mappedImageEnd = getSectionRawEnd(pe.sections[0]!);
  pe.debug = createDebugSection(
    createUnmappedDebugEntry(mappedImageEnd, DEFAULT_FILE_ALIGNMENT >>> 2),
    createUnmappedDebugEntry(
      mappedImageEnd + (DEFAULT_FILE_ALIGNMENT >>> 2) + (DEFAULT_FILE_ALIGNMENT >>> 3),
      DEFAULT_FILE_ALIGNMENT >>> 2
    )
  );

  const warnings = collectPeLayoutWarnings(
    pe,
    mappedImageEnd + (DEFAULT_FILE_ALIGNMENT >>> 1) + (DEFAULT_FILE_ALIGNMENT >>> 3)
  );
  assert.ok(warnings.some(warning => /Debug raw data .*gap in the file tail/i.test(warning)));
});
void test("collectPeLayoutWarnings clamps debug tail end checks to the real file size", () => {
  const pe = createWindowsLayoutSubject(
    createIndexedSection(
      0,
      DEFAULT_SECTION_ALIGNMENT,
      DEFAULT_FILE_ALIGNMENT,
      DEFAULT_FILE_ALIGNMENT,
      DEFAULT_FILE_ALIGNMENT * 2
    )
  );
  const fileSize = getSectionRawEnd(pe.sections[0]!) - (DEFAULT_FILE_ALIGNMENT >>> 1);
  pe.debug = {
    entry: null,
    rawDataRanges: [{ start: fileSize - (DEFAULT_FILE_ALIGNMENT >>> 1), end: fileSize }]
  };

  const warnings = collectPeLayoutWarnings(pe, fileSize);
  assert.ok(
    !warnings.some(warning => /not placed at the end of the file tail/i.test(warning))
  );
});
void test("collectPeLayoutWarnings ignores mapped debug bytes inside a section for tail checks", () => {
  const pe = createWindowsLayoutSubject(
    createIndexedSection(
      0,
      DEFAULT_SECTION_ALIGNMENT,
      DEFAULT_FILE_ALIGNMENT,
      DEFAULT_SECTION_ALIGNMENT,
      DEFAULT_SECTION_ALIGNMENT
    )
  );
  pe.debug = createDebugSection(
    createMappedDebugEntry(pe.sections[0]!, DEFAULT_FILE_ALIGNMENT >>> 2, DEFAULT_FILE_ALIGNMENT >>> 3),
    createMappedDebugEntry(pe.sections[0]!, DEFAULT_FILE_ALIGNMENT, DEFAULT_FILE_ALIGNMENT >>> 3)
  );

  const warnings = collectPeLayoutWarnings(pe, getSectionRawEnd(pe.sections[0]!) + DEFAULT_FILE_ALIGNMENT);
  assert.ok(!warnings.some(warning => /debug raw data begins .*overlaps mapped image/i.test(warning)));
  assert.ok(!warnings.some(warning => /Debug raw data .*gap in the file tail/i.test(warning)));
  assert.ok(!warnings.some(warning => /Debug raw data is not placed at the end of the file tail/i.test(warning)));
});
void test("collectPeLayoutWarnings treats debug bytes covering an entire section raw span as mapped", () => {
  const pe = createWindowsLayoutSubject(
    createIndexedSection(
      0,
      DEFAULT_SECTION_ALIGNMENT,
      DEFAULT_FILE_ALIGNMENT,
      DEFAULT_SECTION_ALIGNMENT,
      DEFAULT_SECTION_ALIGNMENT
    )
  );
  pe.debug = createDebugSection(createMappedDebugEntry(pe.sections[0]!, 0, pe.sections[0]!.sizeOfRawData));

  const warnings = collectPeLayoutWarnings(pe, getSectionRawEnd(pe.sections[0]!) + DEFAULT_FILE_ALIGNMENT);
  assert.ok(!warnings.some(warning => /debug raw data begins .*overlaps mapped image/i.test(warning)));
  assert.ok(!warnings.some(warning => /Debug raw data is not placed at the end of the file tail/i.test(warning)));
});
void test("collectPeLayoutWarnings normalizes unsorted adjacent debug tail ranges", () => {
  const pe = createWindowsLayoutSubject(
    createIndexedSection(0, DEFAULT_SECTION_ALIGNMENT, DEFAULT_FILE_ALIGNMENT)
  );
  const mappedImageEnd = getSectionRawEnd(pe.sections[0]!);
  pe.debug = createDebugSection(
    createUnmappedDebugEntry(mappedImageEnd + (DEFAULT_FILE_ALIGNMENT >>> 2), DEFAULT_FILE_ALIGNMENT >>> 2),
    createUnmappedDebugEntry(mappedImageEnd, DEFAULT_FILE_ALIGNMENT >>> 2)
  );

  const warnings = collectPeLayoutWarnings(pe, mappedImageEnd + (DEFAULT_FILE_ALIGNMENT >>> 1));
  assert.ok(!warnings.some(warning => /Debug raw data .*gap in the file tail/i.test(warning)));
  assert.ok(!warnings.some(warning => /Debug raw data is not placed at the end of the file tail/i.test(warning)));
});
void test("collectPeLayoutWarnings does not require certificates to precede mapped debug bytes", () => {
  const pe = createWindowsLayoutSubject(
    createIndexedSection(
      0,
      DEFAULT_SECTION_ALIGNMENT,
      DEFAULT_FILE_ALIGNMENT,
      DEFAULT_SECTION_ALIGNMENT,
      DEFAULT_SECTION_ALIGNMENT
    )
  );
  const certificateStart = getSectionRawEnd(pe.sections[0]!);
  const certificateSize = DEFAULT_FILE_ALIGNMENT >>> 1;
  pe.dirs = [{ name: "SECURITY", rva: certificateStart, size: certificateSize }];
  pe.debug = createDebugSection(
    createMappedDebugEntry(pe.sections[0]!, DEFAULT_FILE_ALIGNMENT >>> 1, DEFAULT_FILE_ALIGNMENT >>> 3)
  );

  const warnings = collectPeLayoutWarnings(pe, certificateStart + certificateSize);

  assert.ok(
    !warnings.some(warning => /certificate table does not immediately precede debug raw data/i.test(warning))
  );
  assert.ok(
    !warnings.some(warning => /certificate table and debug raw data overlap/i.test(warning))
  );
  assert.ok(
    !warnings.some(warning => /Debug raw data is not placed at the end of the file tail/i.test(warning))
  );
});
