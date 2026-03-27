"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderResources } from "../../renderers/pe/resources.js";

type ResourceLangPreview = {
  lang: number | null;
  size: number;
  codePage?: number;
  previewKind: string;
  previewMime?: string;
  previewDataUrl?: string;
  previewIssues?: string[];
  previewFields?: Array<{ label: string; value: string }>;
  textPreview?: string;
  textEncoding?: string;
  stringTable?: Array<{ id: number; text: string }>;
  messageTable?: { messages: Array<{ id: number; strings: string[] }>; truncated: boolean };
  versionInfo?: {
    fileVersionString?: string;
    productVersionString?: string;
    translations?: Array<{ languageId: number; codePage: number }>;
    stringValues?: Array<{ table: string; key: string; value: string }>;
  };
};

type ResourceEntry = {
  id?: number;
  name?: string;
  langs: ResourceLangPreview[];
};

type ResourceDetail = {
  typeName: string;
  entries: ResourceEntry[];
};

type ResourceSummary = {
  typeName: string;
  kind: string;
  leafCount: number;
};

type ResourceTreeMock = {
  top: ResourceSummary[];
  detail: ResourceDetail[];
  directories?: Array<{
    offset: number;
    timeDateStamp: number;
    majorVersion: number;
    minorVersion: number;
    namedEntries: number;
    idEntries: number;
  }>;
  issues?: string[];
};

const createPeResources = (): ResourceTreeMock => ({
  top: [
    { typeName: "ICON", kind: "id", leafCount: 2 },
    { typeName: "HTML", kind: "name", leafCount: 1 }
  ],
  directories: [
    {
      offset: 0,
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
          langs: [
            {
              lang: 3082,
              size: 192,
              codePage: 1252,
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

void test("renderResources renders preview cells for common resource types", () => {
  const pe = { resources: createPeResources() };
  const out: string[] = [];

  renderResources(pe, out);
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
