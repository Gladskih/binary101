"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { PeResources } from "../../analyzers/pe/resources/index.js";
import { parseMuiResourceConfiguration } from "../../analyzers/pe/resources/mui-config.js";
import { renderResources } from "../../renderers/pe/resources.js";
import { buildMuiResourceConfigurationFixture } from "../fixtures/pe-mui-resource-config-fixture.js";
import { expectDefined } from "../helpers/expect-defined.js";

void test("renderResources gives large MUI and heuristic text previews the full table width", () => {
  const resources: PeResources = {
    top: [],
    detail: [
      {
        typeName: "MUI",
        entries: [
          {
            id: 1,
            name: null,
            langs: [
              {
                lang: 1033,
                size: 160,
                codePage: 0,
                dataRVA: 0,
                reserved: 0,
                previewKind: "muiConfig",
                muiConfig: expectDefined(parseMuiResourceConfiguration(
                  buildMuiResourceConfigurationFixture()
                ))
              }
            ]
          }
        ]
      },
      {
        typeName: "UIFILE",
        entries: [
          {
            id: 101,
            name: null,
            langs: [
              {
                lang: 1033,
                size: 4096,
                codePage: 0,
                dataRVA: 0,
                reserved: 0,
                previewKind: "text",
                textPreview: "<duixml><element id=\"root\" /></duixml>",
                previewFields: [{ label: "Detected", value: "XML/Text (heuristic)" }]
              }
            ]
          }
        ]
      }
    ]
  };
  const out: string[] = [];

  renderResources(resources, out);
  const html = out.join("");

  assert.equal(html.match(/peResourcePreviewWideRow/gu)?.length, 2);
  assert.match(html, /MUI resource config/);
  assert.match(html, /MUI resource configuration/);
  assert.match(html, /XML\/Text \(heuristic\)/);
  assert.match(html, /&lt;duixml>/);
});
