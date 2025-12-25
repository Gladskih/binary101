"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseForUi } from "../../analyzers/index.js";
import type { AnalyzerName, ParsedByAnalyzer } from "../../analyzers/index.js";
import { DOMParser as XmlDomParser } from "@xmldom/xmldom";
import {
  renderElf,
  renderFb2,
  renderGif,
  renderJpeg,
  renderMp3,
  renderMp4,
  renderPcap,
  renderPdf,
  renderPe,
  renderMz,
  renderPng,
  renderWebm,
  renderSevenZip,
  renderTar,
  renderWebp,
  renderZip,
  renderRar,
  renderLnk,
  renderWav,
  renderAvi,
  renderAni,
  renderSqlite
} from "../../renderers/index.js";
import type { ZipParseResult } from "../../analyzers/zip/index.js";
import { createMp3File } from "../fixtures/audio-sample-files.js";
import { createFb2File, createPdfFile } from "../fixtures/document-sample-files.js";
import { createDosMzExe } from "../fixtures/dos-sample-file.js";
import { createElfFile } from "../fixtures/elf-sample-file.js";
import { createGifFile, createJpegFile, createPngFile, createWebpFile } from "../fixtures/image-sample-files.js";
import { createLnkFile } from "../fixtures/lnk-sample-file.js";
import { createMp4File } from "../fixtures/mp4-fixtures.js";
import { createPeFile } from "../fixtures/sample-files-pe.js";
import { createRar5File, createSevenZipFile } from "../fixtures/rar-sevenzip-fixtures.js";
import { createTarFile } from "../fixtures/tar-fixtures.js";
import { createZipFile } from "../fixtures/zip-fixtures.js";
import { createWebmWithCues } from "../fixtures/webm-cues-fixtures.js";
import { createAniFile, createAviFile, createWavFile } from "../fixtures/riff-sample-files.js";
import { createSqliteFile } from "../fixtures/sqlite-fixtures.js";
import { createPcapFile } from "../fixtures/pcap-fixtures.js";

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

const parseOnly = async <Name extends AnalyzerName>(
  file: File,
  expectedAnalyzer: Name
): Promise<ParsedByAnalyzer<Name>> => {
  const result = await parseForUi(file);
  assert.strictEqual(result.analyzer, expectedAnalyzer);
  return result.parsed as ParsedByAnalyzer<Name>;
};

void test("renderers produce readable HTML output", async () => {
  const png = await parseOnly(createPngFile(), "png");
  png.issues = (png.issues || []).concat("synthetic PNG warning");
  const pngHtml = renderPng(png);
  assert.match(pngHtml, /PNG/);
  assert.match(pngHtml, /synthetic PNG warning/);

  const gif = await parseOnly(createGifFile(), "gif");
  gif.comments = [{ text: "hi there", truncated: false }];
  const gifHtml = renderGif(gif);
  assert.match(gifHtml, /GIF/);
  assert.match(gifHtml, /hi there/);

  const jpeg = await parseOnly(createJpegFile(), "jpeg");
  const jpegHtml = renderJpeg(jpeg);
  assert.match(jpegHtml, /JPEG/);

  const webp = await parseOnly(createWebpFile(), "webp");
  const webpHtml = renderWebp(webp);
  assert.match(webpHtml, /WebP/);

  const ani = await parseOnly(createAniFile(), "ani");
  const aniHtml = renderAni(ani);
  assert.match(aniHtml, /ANI/);

  const webm = await parseOnly(createWebmWithCues(), "webm");
  const webmHtml = renderWebm(webm);
  assert.match(webmHtml, /WebM/);
  assert.match(webmHtml, /Tracks/);
  assert.match(webmHtml, /VP8/);
  assert.match(webmHtml, /Opus/);
  assert.match(webmHtml, /UID/);
  assert.match(webmHtml, /Flags/);
  assert.match(webmHtml, /FlagEnabled:/);
  assert.match(webmHtml, /FlagDefault:/);
  assert.match(webmHtml, /FlagForced:/);
  assert.match(webmHtml, /FlagLacing:/);
  assert.match(webmHtml, /CodecPrivate/);
  assert.match(webmHtml, /Cues/);
  assert.match(webmHtml, /Track 1/);

  const mp4 = await parseOnly(createMp4File(), "mp4");
  const mp4Html = renderMp4(mp4);
  assert.match(mp4Html, /MP4/);
  assert.match(mp4Html, /Tracks/);
  assert.match(mp4Html, /Top-level boxes/);

  const pcap = await parseOnly(createPcapFile(), "pcap");
  const pcapHtml = renderPcap(pcap);
  assert.match(pcapHtml, /PCAP/i);

  const avi = await parseOnly(createAviFile(), "avi");
  const aviHtml = renderAvi(avi);
  assert.match(aviHtml, /AVI/);

  const fb2 = await parseOnly(createFb2File(), "fb2");
  const fb2Html = renderFb2(fb2);
  assert.match(fb2Html, /Example/);

  const pdf = await parseOnly(createPdfFile(), "pdf");
  const pdfHtml = renderPdf(pdf);
  assert.match(pdfHtml, /PDF/);

  const mp3 = await parseOnly(createMp3File(), "mp3");
  const mp3Html = renderMp3(mp3);
  assert.match(mp3Html, /MPEG audio/);
  assert.match(mp3Html, /valueHint/);
  assert.match(mp3Html, /optionsRow/);
  assert.match(mp3Html, /CD-quality rate/);

  const wav = await parseOnly(createWavFile(), "wav");
  const wavHtml = renderWav(wav);
  assert.match(wavHtml, /WAVE audio/);

  const lnk = await parseOnly(createLnkFile(), "lnk");
  const lnkHtml = renderLnk(lnk);
  assert.match(lnkHtml, /Shell link header/);
  assert.match(lnkHtml, /LinkTargetIDList/);
  assert.match(lnkHtml, /LocalBasePath \+ CommonPathSuffix/);
  assert.match(lnkHtml, /System\.VolumeId/);
  assert.match(lnkHtml, /System\.Link\.TargetParsingPath/);

  const zip = await parseOnly(createZipFile(), "zip");
  zip.issues = ["central directory synthetic issue"];
  const zipHtml = renderZip(zip);
  assert.match(zipHtml, /ZIP overview/);
  assert.match(zipHtml, /synthetic issue/);

  const tar = await parseOnly(createTarFile(), "tar");
  const tarHtml = renderTar(tar);
  assert.match(tarHtml, /TAR/);

  const elf = await parseOnly(createElfFile(), "elf");
  const elfHtml = renderElf(elf);
  assert.match(elfHtml, /ELF header/);

  const pe = await parseOnly(createPeFile(), "pe");
  const peHtml = renderPe(pe);
  assert.match(peHtml, /PE image/);

  const mz = await parseOnly(createDosMzExe(), "mz");
  const mzHtml = renderMz(mz);
  assert.match(mzHtml, /MS-DOS header/);

  const sevenZip = await parseOnly(createSevenZipFile(), "sevenZip");
  sevenZip.issues.push("synthetic 7z issue");
  const sevenHtml = renderSevenZip(sevenZip);
  assert.match(sevenHtml, /7z overview/);
  assert.match(sevenHtml, /synthetic 7z issue/);

  const rar = await parseOnly(createRar5File(), "rar");
  const rarHtml = renderRar(rar);
  assert.match(rarHtml, /RAR overview/);

  const sqlite = await parseOnly(createSqliteFile(), "sqlite");
  const sqliteHtml = renderSqlite(sqlite);
  assert.match(sqliteHtml, /SQLite database/);
  assert.match(sqliteHtml, /File header/);
  assert.match(sqliteHtml, /sqlite_schema/);
});

void test("renderZip shows extract actions and extraction notices", () => {
  const zip: ZipParseResult = {
    eocd: {
      offset: 0,
      diskNumber: 0,
      centralDirDisk: 0,
      entriesThisDisk: 2,
      totalEntries: 2,
      centralDirSize: 64,
      centralDirOffset: 128,
      commentLength: 0,
      comment: ""
    },
    zip64Locator: null,
    zip64: null,
    centralDirectory: {
      offset: 128,
      size: 64,
      parsedSize: 64,
      truncated: false,
      entries: [
        {
          index: 0,
          fileName: "doc.txt",
          comment: "",
          compressionName: "Stored",
          compressionMethod: 0,
          compressedSize: 3,
          uncompressedSize: 3,
          modTimeIso: "-",
          flags: 0,
          isUtf8: false,
          isEncrypted: false,
          usesDataDescriptor: false,
          crc32: 0,
          diskNumberStart: 0,
          internalAttrs: 0,
          externalAttrs: 0,
          localHeaderOffset: 0,
          dataOffset: 10,
          dataLength: 3
        },
        {
          index: 1,
          fileName: "secret.bin",
          comment: "",
          compressionName: "AES",
          compressionMethod: 99,
          compressedSize: 5,
          uncompressedSize: 5,
          modTimeIso: "-",
          flags: 0,
          isUtf8: false,
          isEncrypted: true,
          usesDataDescriptor: false,
          crc32: 0,
          diskNumberStart: 0,
          internalAttrs: 0,
          externalAttrs: 0,
          localHeaderOffset: 0,
          extractError: "Encrypted entries are not supported for extraction."
        }
      ]
    },
    issues: []
  };

  const html = renderZip(zip);

  assert.match(html, /data-zip-entry="0"/);
  assert.match(html, /Download/);
  assert.match(html, /Encrypted entries are not supported for extraction./);
});
