import assert from "node:assert/strict";
import { DOMParser } from "@xmldom/xmldom";

export const readOverviewDocument = (html: string) => {
  const document = new DOMParser({ onError: assert.fail })
    .parseFromString(`<root>${html}</root>`, "application/xml");
  assert.ok(Array.from(document.documentElement!.childNodes).every(node => node.nodeType === 1));
  return document;
};

export const readOverviewFacts = (html: string): string[][] =>
  Array.from(readOverviewDocument(html).getElementsByTagName("span"))
    .filter(element => element.getAttribute("class") === "workspaceCard__fact")
    .map(element => Array.from(element.getElementsByTagName("span"), child => child.textContent ?? ""));
