"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { PeResources } from "../../analyzers/pe/resources/index.js";
import { renderResources } from "../../renderers/pe/resources.js";

const createPeResources = (): PeResources => ({
  top: [
    { typeName: "ICON", kind: "id", leafCount: 2 },
    { typeName: "HTML", kind: "name", leafCount: 1 }
  ],
  directories: [
    {
      offset: 0,
      characteristics: 0,
      timeDateStamp: 0x2a,
      majorVersion: 1,
      minorVersion: 0,
      namedEntries: 0,
      idEntries: 2
    }
  ],
  issues: ["RT_ICON name directory could not be mapped."],
  detail: [
    {
      typeName: "ICON",
      entries: [
        {
          id: null,
          name: "app",
          langs: [
            {
              lang: 1033,
              size: 2048,
              codePage: 1252,
              dataRVA: 0,
              reserved: 0,
              previewMime: "image/png",
              previewKind: "image",
              previewDataUrl: "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB",
              previewIssues: ["opaque background"]
            }
          ]
        }
      ]
    },
    {
      typeName: "MANIFEST",
      entries: [
        {
          id: 2,
          name: null,
          langs: [
            {
              lang: null,
              size: 96,
              codePage: 0,
              dataRVA: 0,
              reserved: 0,
              previewKind: "text",
              textPreview: "<assembly></assembly>",
              previewIssues: ["invalid schema"]
            }
          ]
        }
      ]
    },
    {
      typeName: "HTML",
      entries: [
        {
          id: 9,
          name: null,
          langs: [
            {
              lang: 1033,
              size: 128,
              codePage: 65001,
              dataRVA: 0,
              reserved: 0,
              previewKind: "html",
              textPreview: "<b>hello</b>",
              textEncoding: "UTF-8",
              previewFields: [
                { label: "Safety", value: "Shown as escaped source; HTML is not executed." }
              ]
            }
          ]
        }
      ]
    },
    {
      typeName: "STRING",
      entries: [
        {
          id: 3,
          name: null,
          langs: [
            {
              lang: 1031,
              size: 512,
              codePage: 1200,
              dataRVA: 0,
              reserved: 0,
              previewKind: "stringTable",
              stringTable: Array.from({ length: 10 }, (_, idx) => ({ id: 32 + idx, text: `s${idx}` })),
              previewIssues: ["String table data ended unexpectedly."]
            }
          ]
        }
      ]
    },
    {
      typeName: "MESSAGETABLE",
      entries: [
        {
          id: null,
          name: "msgs",
          langs: [
            {
              lang: 2057,
              size: 640,
              codePage: 0,
              dataRVA: 0,
              reserved: 0,
              previewKind: "messageTable",
              messageTable: {
                messages: [
                  { id: 1, strings: ["hello"] },
                  { id: 2, strings: ["world"] }
                ],
                truncated: true
              }
            }
          ]
        }
      ]
    },
    {
      typeName: "VERSION",
      entries: [
        {
          id: 4,
          name: null,
          langs: [
            {
              lang: 3082,
              size: 192,
              codePage: 1252,
              dataRVA: 0,
              reserved: 0,
              previewKind: "version",
              versionInfo: {
                fileVersionString: "1.2.3.4",
                productVersionString: "5.6.7.8",
                translations: [{ languageId: 3082, codePage: 1252 }],
                stringValues: [{ table: "0c0a04e4", key: "CompanyName", value: "Binary101" }]
              }
            }
          ]
        }
      ]
    },
    {
      typeName: "OTHER",
      entries: [
        {
          id: 5,
          name: null,
          langs: [
            {
              lang: 0,
              size: 0,
              codePage: 0,
              dataRVA: 0,
              reserved: 0,
              previewKind: "",
              previewIssues: ["Resource bytes could not be read for preview."]
            }
          ]
        }
      ]
    }
  ]
});

void test("renderResources renders preview cells for common resource types", () => {
  const resources = createPeResources();
  const out: string[] = [];

  renderResources(resources, out);
  const html = out.join("");

  assert.match(html, /Resources/);
  assert.match(html, /directory entries → directory strings → data entries/);
  assert.match(html, /ICON/);
  assert.match(html, /RT_ICON name directory could not be mapped/);
  assert.match(html, /IMAGE_RESOURCE_DIRECTORY/);
  assert.match(html, /0x0000002a/);
  assert.match(html, /image\/png/);
  assert.match(html, /opaque background/);
  assert.match(html, /assembly/);
  assert.match(html, /Encoding: UTF-8/);
  assert.match(html, /HTML is not executed/);
  assert.match(html, /English \(United States\)/);
  assert.match(html, /German \(Germany\)/);
  assert.match(html, /#41/);
  assert.match(html, /world/);
  assert.match(html, /1\.2\.3\.4/);
  assert.match(html, /Spanish \(Spain\)/);
  assert.match(html, /Resource bytes could not be read/);
});
