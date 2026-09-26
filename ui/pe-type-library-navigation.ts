// The app uses URL hashes for file history, so section jumps must preserve the current hash.
export const openPeTypeLibrarySection = (event: Event, root: ParentNode): HTMLElement | null => {
  if (!(event.target instanceof Element &&
    event.target.closest("a[href='#pe-type-libraries']"))) return null;
  const section = root.querySelector<HTMLElement>("#pe-type-libraries");
  const details = section?.querySelector<HTMLDetailsElement>(":scope > details");
  if (!section || !details) return null;
  event.preventDefault();
  details.open = true;
  section.scrollIntoView({ block: "start" });
  return section;
};
