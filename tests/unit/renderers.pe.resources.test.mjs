"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderResources } from "../../renderers/pe/resources.js";

const createPeResources = () => ({
  top: [
    { typeName: "ICON", kind: "id", leafCount: 2 },
    { typeName: "HTML", kind: "name", leafCount: 1 }
  ],
  detail: [
    {
      typeName: "ICON",
      entries: [
        {
          name: "app",
          langs: [
            {
              lang: 1033,
              size: 2048,
              codePage: 1252,
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
          langs: [
            {
              lang: null,
              size: 96,
              codePage: 0,
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
          langs: [
            {
              lang: 1033,
              size: 128,
              codePage: 65001,
              previewKind: "html",
              textPreview: "<b>hello</b>",
              textEncoding: "UTF-8"
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
          langs: [
            {
              lang: 1031,
              size: 512,
              codePage: 1200,
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
          name: "msgs",
          langs: [
            {
              lang: 2057,
              size: 640,
              previewKind: "messageTable",
              messageTable: {
                messages: [
                  { id: 1, text: "hello" },
                  { id: 2, text: "world" }
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
          langs: [
            {
              lang: 3082,
              size: 192,
              codePage: 1252,
              previewKind: "version",
              versionInfo: {
                fileVersionString: "1.2.3.4",
                productVersionString: "5.6.7.8"
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
          langs: [
            {
              lang: 0,
              size: 0,
              previewKind: "",
              previewIssues: ["Resource bytes could not be read for preview."]
            }
          ]
        }
      ]
    }
  ]
});

test("renderResources renders preview cells for common resource types", () => {
  const pe = { resources: createPeResources() };
  const out = [];

  renderResources(pe, out);
  const html = out.join("");

  assert.match(html, /Resources/);
  assert.match(html, /ICON/);
  assert.match(html, /image\/png/);
  assert.match(html, /opaque background/);
  assert.match(html, /assembly/);
  assert.match(html, /Encoding: UTF-8/);
  assert.match(html, /more strings not shown/);
  assert.match(html, /more messages not shown/);
  assert.match(html, /1\.2\.3\.4/);
  assert.match(html, /Resource bytes could not be read/);
});
