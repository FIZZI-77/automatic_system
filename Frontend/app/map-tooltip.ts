// Leaflet treats string content as HTML. Keep external names as literal text.
export function mapTooltip(text: string): HTMLElement {
  const element = document.createElement("span");
  element.textContent = text;
  return element;
}
