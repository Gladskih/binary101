"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { detectBinaryType, parseForUi } from "../../analyzers/index.js";
import { DOMParser as XmlDomParser } from "@xmldom/xmldom";
import { createElfFile } from "../fixtures/elf-sample-file.js";
import { createFb2File, createPdfFile } from "../fixtures/document-sample-files.js";
import {
  createGifFile,
  createJpegFile,
  createPngFile,
  createPngWithIhdr,
  createWebpFile
} from "../fixtures/image-sample-files.js";
import { createLnkFile } from "../fixtures/lnk-sample-file.js";
import { createMp3File } from "../fixtures/audio-sample-files.js";
import { createFlacFile } from "../fixtures/flac-fixtures.js";
import { createPeFile } from "../fixtures/sample-files-pe.js";
import {
  createRar4File,
  createRar5File,
  createSevenZipFile
} from "../fixtures/rar-sevenzip-fixtures.js";
import { createDosMzExe } from "../fixtures/dos-sample-file.js";
import { createTarFile } from "../fixtures/tar-fixtures.js";
import { createZipFile } from "../fixtures/zip-fixtures.js";
import { createWebmFile } from "../fixtures/webm-base-fixtures.js";
import { createAniFile, createAviFile, createWavFile } from "../fixtures/riff-sample-files.js";
import { createSampleAsfFile } from "../fixtures/asf-fixtures.js";
import { createMpegPsFile } from "../fixtures/mpegps-fixtures.js";
import { createPcapFile } from "../fixtures/pcap-fixtures.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";
import type { FlacMetadataBlockDetail } from "../../analyzers/flac/types.js";

const textEncoder = new TextEncoder();
class TestDomParser extends XmlDomParser {
  override parseFromString(text: string, type: string) {
    const doc = super.parseFromString(text, type);
    if (!doc.querySelector) {
      doc.querySelector = (selector: string) => {
        const tagName = selector.replace(/[^a-zA-Z0-9:-]/g, "");
        const matches = doc.getElementsByTagName(tagName);
        return matches && matches.length ? matches[0] : null;
      };
    }
    return doc;
  }
}

global.DOMParser = TestDomParser;

const assertParsed = async <TParsed = unknown>(
  file: MockFile | File,
  expectedAnalyzer: string,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  checks?: (parsed: any) => void
): Promise<void> => {
  const { analyzer, parsed } = await parseForUi(file);
  assert.strictEqual(analyzer, expectedAnalyzer);
  assert.ok(parsed, `Expected parsed data for ${expectedAnalyzer}`);
  if (checks) {
    const parsedValue = expectDefined(parsed) as unknown as TParsed;
    checks(parsedValue);
  }
};

void test("detectBinaryType recognizes common binary formats", async () => {
  const detections = await Promise.all([
    detectBinaryType(createPngWithIhdr()),
    detectBinaryType(createGifFile()),
    detectBinaryType(createJpegFile()),
    detectBinaryType(createWebpFile()),
    detectBinaryType(createPdfFile()),
    detectBinaryType(createTarFile()),
    detectBinaryType(createSevenZipFile()),
    detectBinaryType(createRar5File()),
    detectBinaryType(createLnkFile()),
    detectBinaryType(createWebmFile()),
    detectBinaryType(createWavFile()),
    detectBinaryType(createAviFile()),
    detectBinaryType(createAniFile()),
    detectBinaryType(
      new MockFile(textEncoder.encode("plain text sample"), "note.txt", "text/plain")
    ),
    detectBinaryType(createFlacFile())
  ]);

  assert.match(detections[0], /^PNG image/);
  assert.match(detections[1], /^GIF image/);
  assert.match(detections[2], /^JPEG image/);
  assert.match(detections[3], /^WebP image/);
  assert.match(detections[4], /^PDF document/);
  assert.match(detections[5], /tar archive/i);
  assert.match(detections[6], /^7z archive v0\.4/);
  assert.match(detections[7], /^RAR archive/);
  assert.strictEqual(detections[8], "Windows shortcut (.lnk)");
  assert.match(detections[9], /^WebM/);
  assert.match(detections[10], /^WAVE audio/);
  assert.match(detections[11], /^AVI\/DivX video/);
  assert.match(detections[12], /animated cursor/i);
  assert.strictEqual(detections[13], "Text file");
  assert.match(detections[14], /^FLAC audio/);
});

void test("detectBinaryType distinguishes DOS MZ executables from PE", async () => {
  const mzFile = createDosMzExe();
  const detection = await detectBinaryType(mzFile);
  assert.strictEqual(detection, "MS-DOS MZ executable");
  const parsed = await parseForUi(mzFile);
  assert.strictEqual(parsed.analyzer, "mz");
  assert.ok(parsed.parsed);
  assert.strictEqual(parsed.parsed.header.e_magic, "MZ");
  assert.ok(Array.isArray(parsed.parsed.stubStrings));
  assert.ok(parsed.parsed.stubStrings.length >= 1);
});

void test("parseForUi parses and reports PNG layout", async () => {
  await assertParsed(createPngFile(), "png", png => {
    assert.strictEqual(png.ihdr.width, 1);
    assert.strictEqual(png.ihdr.height, 1);
    assert.ok(Array.isArray(png.chunks));
  });
});

void test("parseForUi parses PE headers and sections", async () => {
  await assertParsed(createPeFile(), "pe", pe => {
    assert.strictEqual(pe.coff.NumberOfSections, 1);
    assert.ok(pe.sections);
    assert.ok(pe.coverage);
  });
});

void test("parseForUi parses GIF frames and trailer", async () => {
  await assertParsed(createGifFile(), "gif", gif => {
    assert.ok(gif.hasTrailer);
    assert.ok(Array.isArray(gif.frames));
    assert.strictEqual(gif.frames.length >= 0, true);
  });
});

void test("parseForUi parses JPEG metadata", async () => {
  await assertParsed(createJpegFile(), "jpeg", jpeg => {
    assert.ok(Array.isArray(jpeg.segments));
    assert.ok(jpeg.segmentCount >= 1);
  });
});

void test("parseForUi parses WebP chunks", async () => {
  await assertParsed(createWebpFile(), "webp", webp => {
    assert.ok(Array.isArray(webp.chunks));
  });
});

void test("parseForUi parses WAV audio", async () => {
  await assertParsed(createWavFile(), "wav", wav => {
    assert.strictEqual(wav.format?.channels, 1);
    assert.ok(wav.data?.durationSeconds);
  });
});

void test("parseForUi parses AVI headers and streams", async () => {
  await assertParsed(createAviFile(), "avi", avi => {
    assert.strictEqual(avi.mainHeader?.width, 320);
    assert.strictEqual(avi.streams.length, 1);
    assert.strictEqual(avi.streams[0]?.header?.type, "vids");
  });
});

void test("parseForUi parses ASF headers and streams", async () => {
  await assertParsed(createSampleAsfFile(), "asf", asf => {
    assert.strictEqual(asf.streams.length, 2);
    assert.ok(asf.contentDescription?.title);
  });
});

void test("parseForUi parses ANI metadata", async () => {
  await assertParsed(createAniFile(), "ani", ani => {
    assert.strictEqual(ani.header?.frameCount, 2);
    assert.ok(ani.frames >= 2);
  });
});

void test("parseForUi parses FB2 XML", async () => {
  await assertParsed(createFb2File(), "fb2", fb2 => {
    assert.ok(fb2.title);
    assert.ok(fb2.bodyCount >= 0);
  });
});

void test("parseForUi parses PDF cross-reference data", async () => {
  await assertParsed(createPdfFile(), "pdf", pdf => {
    assert.ok(pdf.header);
    assert.ok(pdf.xref);
    assert.ok(Array.isArray(pdf.issues));
  });
});

void test("parseForUi parses Windows shortcuts", async () => {
  await assertParsed(createLnkFile(), "lnk", lnk => {
    assert.strictEqual(lnk.linkInfo.localBasePath, "C:\\Program Files\\Example");
    assert.strictEqual(lnk.stringData.relativePath, ".\\Example\\app.exe");
    assert.ok(Array.isArray(lnk.extraData.blocks));
    const propertyStore = lnk.extraData.blocks.find(
      (block: { signature?: number; parsed?: { storages?: unknown[] } }) =>
        block.signature === 0xa0000009
    );
    assert.ok(propertyStore?.parsed?.storages?.length);
  });
});

void test("parseForUi parses MP3 frames and summary", async () => {
  await assertParsed(createMp3File(), "mp3", mp3 => {
    assert.strictEqual(mp3.isMp3, true);
    assert.ok(mp3.mpeg.firstFrame);
    assert.ok(mp3.summary);
  });
});

void test("parseForUi parses FLAC stream info and metadata blocks", async () => {
  await assertParsed(createFlacFile(), "flac", flac => {
    assert.strictEqual(flac.streamInfo?.sampleRate, 44100);
    assert.strictEqual(flac.streamInfo?.channels, 2);
    assert.ok(Array.isArray(flac.blocks));
    const comments = flac.blocks.find(
      (block: FlacMetadataBlockDetail) => block.type === "VORBIS_COMMENT"
    );
    assert.ok(comments);
  });
});

void test("parseForUi parses TAR headers", async () => {
  await assertParsed(createTarFile(), "tar", tar => {
    assert.strictEqual(tar.isTar, true);
    assert.ok(Array.isArray(tar.entries));
    assert.ok(tar.entries[0]);
  });
});

void test("parseForUi parses WebM metadata and tracks", async () => {
  await assertParsed(createWebmFile(), "webm", webm => {
    assert.strictEqual(webm.docType, "webm");
    assert.ok(webm.segment?.info?.durationSeconds);
    assert.ok(webm.segment?.tracks.length);
  });
});

void test("parseForUi parses MPEG Program Streams (MPEG-PS)", async () => {
  await assertParsed(createMpegPsFile(), "mpegps", mpegps => {
    assert.strictEqual(mpegps.packHeaders.totalCount >= 1, true);
    assert.strictEqual(mpegps.pes.totalPackets >= 1, true);
  });
});

void test("parseForUi parses PCAP capture files", async () => {
  await assertParsed(createPcapFile(), "pcap", pcap => {
    assert.strictEqual(pcap.header.network, 1);
    assert.strictEqual(pcap.packets.totalPackets >= 1, true);
  });
});

void test("parseForUi parses RAR v4 and v5 headers", async () => {
  await assertParsed(createRar4File(), "rar", rar => {
    assert.strictEqual(rar.version, 4);
    assert.ok(rar.entries.length >= 1);
  });
  await assertParsed(createRar5File(), "rar", rar => {
    assert.strictEqual(rar.version, 5);
    assert.ok(rar.entries.length >= 1);
  });
});

void test("parseForUi parses ZIP EOCD", async () => {
  await assertParsed(createZipFile(), "zip", zip => {
    assert.ok(zip.eocd);
    assert.ok(zip.centralDirectory);
  });
});

void test("parseForUi parses ELF header and sections", async () => {
  await assertParsed(createElfFile(), "elf", elf => {
    assert.strictEqual(elf.ident.className, "ELF64");
    assert.ok(Array.isArray(elf.sections));
  });
});

void test("parseForUi parses 7z start header even when next header is unknown", async () => {
  await assertParsed(createSevenZipFile(), "sevenZip", sevenZip => {
    assert.strictEqual(sevenZip.is7z, true);
    assert.ok(Array.isArray(sevenZip.issues));
    assert.ok(sevenZip.nextHeader);
  });
});
