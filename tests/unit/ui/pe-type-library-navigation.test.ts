import assert from "node:assert/strict";
import { test } from "node:test";
import { openPeTypeLibrarySection } from "../../../ui/pe-type-library-navigation.js";
import { FakeElement, installDom } from "../../fixtures/pe-lazy-section-dom.js";

const navigation = () => {
  const root = new FakeElement("DIV");
  const section = new FakeElement("SECTION");
  const details = new FakeElement("DETAILS");
  const link = new FakeElement("A");
  const dom = installDom(section);
  const events: string[] = [];
  link.closest = () => link;
  section.setQuery(":scope > details", details);
  root.setQuery("#pe-type-libraries", section);
  Object.assign(section, { scrollIntoView: () => events.push("scroll") });
  const event = { target: link, preventDefault: () => events.push("preventDefault") };
  return { root, section, details, link, dom, events, event };
};

void test("TYPELIB navigation opens the section while preserving the file history hash", () => {
  const fixture = navigation();
  try {
    assert.equal(openPeTypeLibrarySection(fixture.event as unknown as Event,
      fixture.root as unknown as ParentNode), fixture.section);
    assert.equal(fixture.details.open, true);
    assert.deepEqual(fixture.events, ["preventDefault", "scroll"]);
  } finally { fixture.dom.restore(); }
});

void test("TYPELIB navigation ignores unrelated clicks and absent targets", () => {
  const fixture = navigation();
  try {
    fixture.link.closest = () => null;
    assert.equal(openPeTypeLibrarySection(fixture.event as unknown as Event,
      fixture.root as unknown as ParentNode), null);
    assert.equal(openPeTypeLibrarySection({ target: null } as unknown as Event,
      fixture.root as unknown as ParentNode), null);
    assert.deepEqual(fixture.events, []);
  } finally { fixture.dom.restore(); }
});

void test("TYPELIB navigation tolerates missing sections or details", () => {
  const fixture = navigation();
  try {
    assert.equal(openPeTypeLibrarySection(fixture.event as unknown as Event,
      new FakeElement("DIV") as unknown as ParentNode), null);
    fixture.root.setQuery("#pe-type-libraries", new FakeElement("SECTION"));
    assert.equal(openPeTypeLibrarySection(fixture.event as unknown as Event,
      fixture.root as unknown as ParentNode), null);
    assert.deepEqual(fixture.events, []);
  } finally { fixture.dom.restore(); }
});
