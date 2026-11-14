import assert from "node:assert/strict";
import { test } from "node:test";
import { renderWorkspaceHeading } from "../../../ui/workspace-heading.js";
import type { WorkspaceSection } from "../../../ui/workspace-sections.js";

const fixture = () => {
  const classes = new Set<string>();
  const nodes = new Map(["workspaceTitle", "workspaceDescription", "workspaceHeading", "inspectionWorkspace"].map(id =>
    [id, { textContent: "", dataset: {} as Record<string, string>, title: "", hidden: false,
      classList: { contains: (name: string) => classes.has(name) },
      removeAttribute(name: string) { assert.equal(name, "title"); this.title = ""; } }]));
  // This fixture implements the document lookup and heading attributes used by the presenter.
  return { nodes, classes, root: { getElementById: (id: string) => nodes.get(id) } as Document };
};

void test("section headings identify supplemental analysis and clear it for native structures", () => {
  const state = fixture();
  const section = { title: "Analysis", description: "Recorded findings", origin: "supplemental" } as WorkspaceSection;

  renderWorkspaceHeading(state.root, section, "analysis");

  assert.equal(state.nodes.get("workspaceTitle")!.textContent, "Analysis");
  assert.equal(state.nodes.get("workspaceDescription")!.textContent, "Recorded findings");
  assert.equal(state.nodes.get("workspaceHeading")!.dataset["analysisOrigin"], "supplemental");
  assert.equal(state.nodes.get("workspaceHeading")!.title, "Supplemental analysis");
  renderWorkspaceHeading(state.root, { ...section, origin: undefined }, "native");
  assert.equal(state.nodes.get("workspaceHeading")!.dataset["analysisOrigin"], undefined);
  assert.equal(state.nodes.get("workspaceHeading")!.title, "");
});

for (const [key, title] of [["search", "Search results"], ["hashes", "File hashes"], ["native", "Analysis"]]) {
  void test(`virtual view ${key} supplies its own title without a description`, () => {
    const state = fixture();

    renderWorkspaceHeading(state.root, undefined, key!);

    assert.equal(state.nodes.get("workspaceTitle")!.textContent, title);
    assert.equal(state.nodes.get("workspaceDescription")!.textContent, "");
  });
}

void test("previews and continuous reports avoid duplicate headings while tools retain theirs", () => {
  const state = fixture();

  renderWorkspaceHeading(state.root, { title: "Preview", description: "" } as WorkspaceSection, "preview");
  assert.equal(state.nodes.get("workspaceHeading")!.hidden, true);
  state.classes.add("workspaceContinuous");
  renderWorkspaceHeading(state.root, undefined, "native");
  assert.equal(state.nodes.get("workspaceHeading")!.hidden, true);
  renderWorkspaceHeading(state.root, undefined, "hashes");
  assert.equal(state.nodes.get("workspaceHeading")!.hidden, false);
});
