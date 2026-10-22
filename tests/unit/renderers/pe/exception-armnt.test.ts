import assert from "node:assert/strict";
import { test } from "node:test";
import { renderArmntPackedStatistics } from "../../../../renderers/pe/exception-armnt.js";
import { createArmntPackedStatistics, recordArmntPackedStatistics } from "../../../../analyzers/pe/exception/armnt-packed-statistics.js";
import { armntPackedWord } from "../../../fixtures/pe-armnt-unwind.js";
import { DOMParser } from "@xmldom/xmldom";

const parseStatistics = (html: string) => {
  const document = new DOMParser({ onError: assert.fail }).parseFromString(`<root>${html}</root>`, "application/xml");
  const root = document.documentElement!;
  assert.equal(Array.from(root.childNodes).filter(node => node.nodeType === 3 && node.textContent?.trim()).length, 0);
  const definitions = Array.from(document.getElementsByTagName("dl"), list => {
    assert.ok(list.textContent != null);
    const fields = Array.from(list.childNodes).filter(node => node.nodeType === 1);
    assert.equal(list.textContent.replace(/\s/g, ""), fields.map(node => node.textContent).join("").replace(/\s/g, ""));
    return fields.map(node => node.textContent);
  }).flat();
  const tables = Array.from(document.getElementsByTagName("table"), table => {
    const caption = table.getElementsByTagName("caption")[0]!.textContent;
    const headings = Array.from(table.getElementsByTagName("th"), cell => cell.textContent);
    const rows = Array.from(table.getElementsByTagName("tbody")[0]!.getElementsByTagName("tr"), row => {
      assert.equal(row.getElementsByTagName("td")[1]!.getAttribute("class"), "peNumeric");
      return Array.from(row.getElementsByTagName("td"), cell => cell.textContent);
    });
    assert.equal(table.getElementsByTagName("th")[1]!.getAttribute("class"), "peNumeric");
    assert.ok(table.textContent != null);
    assert.equal(table.textContent.replace(/\s/g, ""),
      `${caption}${headings.join("")}${rows.flat().join("")}`.replace(/\s/g, ""));
    return { caption, headings, rows };
  });
  return { definitions, tables };
};

void test("ARMNT packed statistics omit empty inventories", () => {
  assert.equal(renderArmntPackedStatistics(createArmntPackedStatistics()), "");
});

void test("ARMNT packed statistics retain meaningful return and register names with folding details", () => {
  const statistics = createArmntPackedStatistics();
  recordArmntPackedStatistics(statistics,
    armntPackedWord() | (1 << 15) | (1 << 20) | (1 << 21) | (0x3ff << 22));
  const html = renderArmntPackedStatistics(statistics);

  assert.match(html, /Packed .pdata entries<\/dt><dd>1<\/dd>/);
  assert.match(html, /Parameter homes/);
  assert.match(html, /LR saves/);
  assert.match(html, /Frame chains/);
  assert.match(html, /Prolog adjustments folded into pushes/);
  assert.match(html, /Epilog adjustments folded into pops/);
  assert.match(html, /16 B \(16 bytes\)/);
  assert.match(html, /16-bit branch/);
  assert.match(html, /Encoded nonvolatile register groups/);
  assert.match(html, />None<\/td>/);
  assert.match(html, /class="peNumeric"/);
  assert.doesNotMatch(html, /0x|<th>RVA|<details/);
  assert.deepEqual(parseStatistics(html), {
    definitions: ["Packed .pdata entries", "1", "Parameter homes", "1", "LR saves", "1",
      "Frame chains (r11/LR)", "1", "Prolog adjustments folded into pushes", "1",
      "Epilog adjustments folded into pops", "1", "Largest encoded local stack adjustment", "16 B (16 bytes)"],
    tables: [
      { caption: "Packed return modes", headings: ["Return", "Entries"], rows: [["16-bit branch", "1"]] },
      { caption: "Encoded nonvolatile register groups", headings: ["Group", "Entries"], rows: [["None", "1"]] }
    ]
  });
  assert.match(html, /Register groups describe the explicit nonvolatile group/);
  assert.match(html, /parameter homes, LR saves and frame chains are counted separately/);
  assert.match(html, /Stack adjustments exclude those register saves and parameter homes/);
});

void test("ARMNT statistics omit zero counters and escape register-group labels", () => {
  const html = renderArmntPackedStatistics({ ...createArmntPackedStatistics(),
    returnKinds: { popPc: 2, branch16: 0, branch32: 1, noEpilog: 1 },
    registerGroups: { 'r4-<unsafe>&"': 1 } });

  assert.match(html, /POP PC/);
  assert.match(html, /32-bit branch/);
  assert.match(html, /No epilog/);
  assert.doesNotMatch(html, /<unsafe>|<dt>Parameter homes|<dt>LR saves|<dt>Frame chains|<dt>Largest/);
  assert.match(html, /&lt;unsafe&gt;&amp;&quot;/);
});

void test("ARMNT partial statistics keep no empty register table", () => {
  const html = renderArmntPackedStatistics({ ...createArmntPackedStatistics(),
    returnKinds: { popPc: 0, branch16: 1, branch32: 0, noEpilog: 0 } });

  assert.equal([...html.matchAll(/<table /g)].length, 1);
  assert.doesNotMatch(html, /Encoded nonvolatile register groups/);
  assert.deepEqual(parseStatistics(html).definitions, ["Packed .pdata entries", "1"]);
});

void test("ARMNT inventories omit zero entries and sort by count with numeric register order", () => {
  const html = renderArmntPackedStatistics({ ...createArmntPackedStatistics(),
    returnKinds: { popPc: 1, branch16: 0, branch32: 3, noEpilog: 1 },
    registerGroups: { "r4-r10": 1, "r4-r6": 1, "r4-r11": 1, d8: 4 } });

  assert.deepEqual(parseStatistics(html).tables, [
    { caption: "Packed return modes", headings: ["Return", "Entries"],
      rows: [["32-bit branch", "3"], ["No epilog", "1"], ["POP PC", "1"]] },
    { caption: "Encoded nonvolatile register groups", headings: ["Group", "Entries"],
      rows: [["d8", "4"], ["r4-r6", "1"], ["r4-r10", "1"], ["r4-r11", "1"]] }
  ]);
});
