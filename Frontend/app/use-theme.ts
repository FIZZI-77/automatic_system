"use client";

import { useCallback, useEffect, useSyncExternalStore } from "react";

export type Theme = "light" | "dark";
const storageKey = "city-ui-theme-v2";
const changeEvent = "city-theme-changed";
let fallbackTheme: Theme = "light";

function readTheme(): Theme {
  try {
    const stored = window.localStorage.getItem(storageKey);
    return stored === "dark" || stored === "light" ? stored : fallbackTheme;
  } catch {
    return fallbackTheme;
  }
}

function serverTheme(): Theme {
  return "light";
}

function subscribe(listener: () => void) {
  window.addEventListener("storage", listener);
  window.addEventListener(changeEvent, listener);
  return () => {
    window.removeEventListener("storage", listener);
    window.removeEventListener(changeEvent, listener);
  };
}

export function useTheme() {
  const theme = useSyncExternalStore(subscribe, readTheme, serverTheme);
  const toggleTheme = useCallback(() => {
    fallbackTheme = readTheme() === "light" ? "dark" : "light";
    try {
      window.localStorage.setItem(storageKey, fallbackTheme);
    } catch {
      // В браузере с запрещённым хранилищем тема действует до перезагрузки.
    }
    window.dispatchEvent(new Event(changeEvent));
  }, []);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    return () => {
      delete document.documentElement.dataset.theme;
    };
  }, [theme]);

  return [theme, toggleTheme] as const;
}
