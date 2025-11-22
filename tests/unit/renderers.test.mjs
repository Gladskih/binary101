"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseForUi } from "../../analyzers/index.js";
import { DOMParser as XmlDomParser } from "@xmldom/xmldom";
import {
  renderElf,
  renderFb2,
  renderGif,
  renderJpeg,
  renderMp3,
  renderPdf,
  renderPe,
  renderPng,
  renderSevenZip,
  renderTar,
  renderWebp,
  renderZip,
  renderRar
} from "../../renderers/index.js";
import {
  createElfFile,
  createFb2File,
  createGifFile,
  createJpegFile,
  createMp3File,
  createPdfFile,
  createPeFile,
  createPngFile,
  createSevenZipFile,
  createTarFile,
  createWebpFile,
  createZipFile,
  createRar5File
} from "../fixtures/sample-files.mjs";

class TestDomParser extends XmlDomParser {
  parseFromString(text, type) {
    const doc = super.parseFromString(text, type);
    if (!doc.querySelector) {
      doc.querySelector = selector => {
        const tagName = selector.replace(/[^a-zA-Z0-9:-]/g, "");
        const matches = doc.getElementsByTagName(tagName);
        return matches && matches.length ? matches[0] : null;
      };
    }
    return doc;
  }
}

global.DOMParser = TestDomParser;

const parseOnly = async file => (await parseForUi(file)).parsed;

test("renderers produce readable HTML output", async () => {
  const png = await parseOnly(createPngFile());
  png.issues = (png.issues || []).concat("synthetic PNG warning");
  const pngHtml = renderPng(png);
  assert.match(pngHtml, /PNG/);
  assert.match(pngHtml, /synthetic PNG warning/);

  const gif = await parseOnly(createGifFile());
  gif.comments = [{ text: "hi there" }];
  const gifHtml = renderGif(gif);
  assert.match(gifHtml, /GIF/);
  assert.match(gifHtml, /hi there/);

  const jpeg = await parseOnly(createJpegFile());
  const jpegHtml = renderJpeg(jpeg);
  assert.match(jpegHtml, /JPEG/);

  const webp = await parseOnly(createWebpFile());
  const webpHtml = renderWebp(webp);
  assert.match(webpHtml, /WebP/);

  const fb2 = await parseOnly(createFb2File());
  const fb2Html = renderFb2(fb2);
  assert.match(fb2Html, /Example/);

  const pdf = await parseOnly(createPdfFile());
  const pdfHtml = renderPdf(pdf);
  assert.match(pdfHtml, /PDF/);

  const mp3 = await parseOnly(createMp3File());
  const mp3Html = renderMp3(mp3);
  assert.match(mp3Html, /MPEG audio/);

  const zip = await parseOnly(createZipFile());
  zip.issues = ["central directory synthetic issue"];
  const zipHtml = renderZip(zip);
  assert.match(zipHtml, /ZIP overview/);
  assert.match(zipHtml, /synthetic issue/);

  const tar = await parseOnly(createTarFile());
  const tarHtml = renderTar(tar);
  assert.match(tarHtml, /TAR/);

  const elf = await parseOnly(createElfFile());
  const elfHtml = renderElf(elf);
  assert.match(elfHtml, /ELF header/);

  const pe = await parseOnly(createPeFile());
  const peHtml = renderPe(pe);
  assert.match(peHtml, /PE image/);

  const sevenZip = await parseOnly(createSevenZipFile());
  sevenZip.issues.push("synthetic 7z issue");
  const sevenHtml = renderSevenZip(sevenZip);
  assert.match(sevenHtml, /7z overview/);
  assert.match(sevenHtml, /synthetic 7z issue/);

  const rar = await parseOnly(createRar5File());
  const rarHtml = renderRar(rar);
  assert.match(rarHtml, /RAR overview/);
});
