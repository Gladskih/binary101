export interface WorkspaceSection {
  key: string;
  title: string;
  description: string;
  origin: "supplemental" | undefined;
  element: HTMLElement;
  details: HTMLDetailsElement | null;
}

export const sectionDetails = (element: HTMLElement): HTMLDetailsElement | null =>
  element instanceof HTMLDetailsElement ? element :
    element.querySelector<HTMLDetailsElement>(":scope > details");

const sectionHeading = (element: HTMLElement): Element | null =>
  sectionDetails(element)?.querySelector(":scope > summary") ??
  element.querySelector(":scope > h2, :scope > h3, :scope > h4");

const sectionTitle = (element: HTMLElement): string => {
  const heading = sectionHeading(element);
  return (heading?.querySelector("b, .detailsSummaryTitle") ?? heading)?.textContent?.trim() ||
    (element.querySelector(".imagePreview, .videoPreview, .audioPreview") ||
      element.matches(".imagePreview, .videoPreview, .audioPreview") ? "Preview" : "Analysis");
};

const wrapLooseContent = (root: HTMLElement): void => {
  let wrapper: HTMLElement | null = null;
  for (const element of Array.from(root.children)) {
    if (!(element instanceof HTMLElement)) continue;
    if (element.matches("section, details, [data-workspace-section]") || sectionDetails(element)) {
      wrapper = null;
      continue;
    }
    if (element.matches("h2, h3, h4") || !wrapper) {
      wrapper = document.createElement("section");
      wrapper.dataset["workspaceSection"] = "";
      root.insertBefore(wrapper, element);
    }
    wrapper.append(element);
  }
};

export const collectWorkspaceSections = (root: HTMLElement): WorkspaceSection[] => {
  wrapLooseContent(root);
  return Array.from(root.children).filter((element): element is HTMLElement =>
    element instanceof HTMLElement
  ).map((element, index) => {
    const title = sectionTitle(element);
    const key = element.dataset["peLazySection"] ?? element.dataset["elfLazySection"] ??
      (element.id || `${index}-${title}`);
    element.classList.add("workspacePanel");
    return {
      key: `analysis-${key}`,
      title,
      description: sectionHeading(element)?.textContent?.trim().replace(title, "")
        .replace(/^\s*[-–—]\s*/, "") ?? "",
      origin: element.dataset["analysisOrigin"] === "supplemental" ? "supplemental" : undefined,
      element,
      details: sectionDetails(element)
    };
  });
};
