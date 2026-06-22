"use strict";

import assert from "node:assert/strict";
import test from "node:test";
import type { ElfParseResult } from "../../../analyzers/elf/types.js";
import type { PeParseResult, PeWindowsParseResult } from "../../../analyzers/pe/index.js";
import { createPeWithImportLinking } from "../../fixtures/pe-import-linking-fixture.js";
import {
  ELF_INSTRUCTION_SETS_PANEL_ID
} from "../../../renderers/elf/disassembly.js";
import {
  PE_DELAY_IMPORTS_PANEL_ID,
  PE_IMPORTS_PANEL_ID
} from "../../../renderers/pe/import-sections.js";
import {
  PE_INSTRUCTION_SETS_PANEL_ID
} from "../../../renderers/pe/disassembly.js";
import {
  PE_ENTRYPOINT_DISASSEMBLY_PANEL_ID
} from "../../../renderers/pe/entrypoint-disassembly.js";
import { PE_OVERLAY_PANEL_ID } from "../../../renderers/pe/overlay.js";
import {
  refreshElfInstructionSetsPanel,
  refreshPeDisassemblyPanels,
  refreshPeEntrypointDisassemblyPanel,
  refreshPeInstructionSetsPanel,
  refreshPeOverlayPanel
} from "../../../ui/analysis-panel-refresh.js";

type GlobalDom = {
  HTMLElement?: unknown;
  document?: unknown;
};

class FakePanel {
  markup = "";
  constructor(
    private readonly panelId: string,
    private readonly panels: Map<string, FakePanel>
  ) {}
  querySelectorAll(): [] {
    return [];
  }
  set outerHTML(markup: string) {
    const replacement = new FakePanel(this.panelId, this.panels);
    replacement.markup = markup;
    this.panels.set(this.panelId, replacement);
  }
}

const installPanelDom = () => {
  const globals = globalThis as unknown as GlobalDom;
  const originalHTMLElement = globals.HTMLElement;
  const originalDocument = globals.document;
  const panels = new Map<string, FakePanel>();
  globals.HTMLElement = FakePanel;
  globals.document = { getElementById: (id: string): FakePanel | null => panels.get(id) ?? null };
  const addPanel = (id: string): void => { panels.set(id, new FakePanel(id, panels)); };
  return {
    addPanel,
    markup: (id: string): string => panels.get(id)?.markup ?? "",
    restore: (): void => {
      globals.HTMLElement = originalHTMLElement;
      globals.document = originalDocument;
    }
  };
};

const createPe = (): PeWindowsParseResult => ({
  coff: { Machine: 0x8664 },
  opt: { AddressOfEntryPoint: 0x1000 },
  sections: []
}) as unknown as PeWindowsParseResult;

void test("refreshPeInstructionSetsPanel replaces only its rendered panel", () => {
  const dom = installPanelDom();
  try {
    dom.addPanel(PE_INSTRUCTION_SETS_PANEL_ID);
    refreshPeInstructionSetsPanel(createPe());
    assert.match(dom.markup(PE_INSTRUCTION_SETS_PANEL_ID), /Instruction-set analysis/);
  } finally {
    dom.restore();
  }
});

void test("refreshPeDisassemblyPanels renders ISA and import regions from one PE model", () => {
  const dom = installPanelDom();
  try {
    const pe = createPeWithImportLinking();
    dom.addPanel(PE_INSTRUCTION_SETS_PANEL_ID);
    dom.addPanel(PE_IMPORTS_PANEL_ID);
    dom.addPanel(PE_DELAY_IMPORTS_PANEL_ID);

    refreshPeDisassemblyPanels(pe);

    assert.match(dom.markup(PE_INSTRUCTION_SETS_PANEL_ID), /Instruction-set analysis/);
    assert.match(dom.markup(PE_IMPORTS_PANEL_ID), /Direct IAT refs/);
    assert.match(dom.markup(PE_DELAY_IMPORTS_PANEL_ID), /Direct IAT refs/);
  } finally {
    dom.restore();
  }
});

void test("refreshPeEntrypointDisassemblyPanel replaces only its rendered panel", () => {
  const dom = installPanelDom();
  try {
    dom.addPanel(PE_ENTRYPOINT_DISASSEMBLY_PANEL_ID);
    refreshPeEntrypointDisassemblyPanel(createPe());
    assert.match(dom.markup(PE_ENTRYPOINT_DISASSEMBLY_PANEL_ID), /Entrypoint disassembly/);
  } finally {
    dom.restore();
  }
});

void test("refreshPeOverlayPanel replaces only its rendered panel", () => {
  const dom = installPanelDom();
  try {
    dom.addPanel(PE_OVERLAY_PANEL_ID);
    refreshPeOverlayPanel({
      overlay: { ranges: [], warnings: ["overlay warning"] }
    } as unknown as PeParseResult);
    assert.match(dom.markup(PE_OVERLAY_PANEL_ID), /Overlay/);
  } finally {
    dom.restore();
  }
});

void test("refreshElfInstructionSetsPanel replaces only its rendered panel", () => {
  const dom = installPanelDom();
  try {
    dom.addPanel(ELF_INSTRUCTION_SETS_PANEL_ID);
    refreshElfInstructionSetsPanel({} as ElfParseResult);
    assert.match(dom.markup(ELF_INSTRUCTION_SETS_PANEL_ID), /Instruction sets/);
  } finally {
    dom.restore();
  }
});

void test("panel refresh is a no-op when the panel is absent", () => {
  const dom = installPanelDom();
  try {
    refreshPeInstructionSetsPanel(createPe());
    assert.equal(dom.markup(PE_INSTRUCTION_SETS_PANEL_ID), "");
  } finally {
    dom.restore();
  }
});
