import type { ReactNode } from "react";

// Shared outline icons keep navigation recognisable at every font size.
const icons = {
  home: <><path d="m3 10 9-7 9 7" /><path d="M5 9v12h5v-7h4v7h5V9" /></>,
  clipboard: <><rect x="5" y="4" width="14" height="17" rx="2" /><rect x="9" y="2" width="6" height="4" rx="1" /><path d="M9 11h6M9 16h6" /></>,
  plus: <><circle cx="12" cy="12" r="9" /><path d="M12 8v8M8 12h8" /></>,
  bell: <><path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9M10 21h4" /></>,
  user: <><circle cx="12" cy="7" r="4" /><path d="M4 21v-2a8 8 0 0 1 16 0v2" /></>,
  map: <><path d="m3 5 6-2 6 2 6-2v16l-6 2-6-2-6 2ZM9 3v16M15 5v16" /></>,
  users: <><circle cx="9" cy="7" r="4" /><path d="M2 21v-2a7 7 0 0 1 14 0v2M17 3a4 4 0 0 1 0 8M22 21v-2a7 7 0 0 0-4-6" /></>,
  chart: <><path d="M3 3v18h18M8 16v-5M13 16V7M18 16V4" /></>,
  clock: <><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></>,
  building: <><rect x="7" y="3" width="10" height="18" rx="1" /><path d="M7 9H3v12h18V9h-4M10 7h4M10 11h4M10 15h4M11 21v-3h2v3" /></>,
  book: <><path d="M12 5C9 3 6 3 2 4v16c4-1 7-1 10 1 3-2 6-2 10-1V4c-4-1-7-1-10 1ZM12 5v16" /></>,
  graduation: <><path d="m2 8 10-5 10 5-10 5ZM6 10v7c4 3 8 3 12 0v-7M22 8v7" /></>,
  badge: <><rect x="3" y="4" width="18" height="16" rx="2" /><circle cx="9" cy="10" r="2" /><path d="M6 16a3 3 0 0 1 6 0M15 9h3M15 13h3" /></>,
  checklist: <><path d="m3 6 2 2 3-4M11 6h10M3 13l2 2 3-4M11 13h10M5 20h2M11 20h10" /></>,
  report: <><path d="M14 2H5v20h14V7ZM14 2v5h5M8 17v-3M12 17v-6M16 17v-2" /></>,
  history: <><path d="M3 11a9 9 0 1 1 2 7M3 4v7h7M12 7v5l3 2" /></>,
  settings: <><path d="m9 3-1 3-3 1-2 3 2 2-1 3 2 3h3l2 3h3l1-3 3-1 2-3-2-2 1-3-2-3h-3l-2-3Z" /><circle cx="12" cy="12" r="3" /></>,
  zones: <><path d="M8 3H3v5M16 3h5v5M21 16v5h-5M8 21H3v-5M17 9c0 4-5 8-5 8S7 13 7 9a5 5 0 0 1 10 0Z" /><circle cx="12" cy="9" r="1.5" /></>,
  logout: <><path d="M9 3H4v18h5M9 12h12M17 8l4 4-4 4" /></>,
} satisfies Record<string, ReactNode>;

export type NavigationIconName = keyof typeof icons;

export function NavigationIcon({ name }: { name: NavigationIconName }) {
  return (
    <svg
      className="navigation-icon"
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {icons[name]}
    </svg>
  );
}
