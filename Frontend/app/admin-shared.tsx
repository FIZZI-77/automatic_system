"use client";

import { ReactNode } from "react";

export type Notice = (message: string) => void;

export type Dict = Record<string, unknown>;

export function text(value: unknown, fallback: unknown = "—") {
  if (value === null || value === undefined || value === "")
    return String(fallback);
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

export function timestamp(value: unknown) {
  const source =
    typeof value === "object" && value !== null && "seconds" in value
      ? (value as { seconds?: unknown }).seconds
      : value;
  const number = Number(source);
  if (!Number.isFinite(number) || number <= 0) return "—";
  return new Date(
    number > 10_000_000_000 ? number : number * 1000,
  ).toLocaleString("ru-RU");
}

export function enumLabel(value: unknown, labels: string[]) {
  return typeof value === "number"
    ? labels[value] || "UNKNOWN"
    : text(value, "UNKNOWN");
}

export function Modal({
  title,
  children,
  onClose,
  className = "",
}: {
  title: string;
  children: ReactNode;
  onClose: () => void;
  className?: string;
}) {
  return (
    <div
      className="ops-modal"
      role="presentation"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div
        className={`ops-modal-card ${className}`}
        role="dialog"
        aria-modal="true"
      >
        <button className="modal-close" onClick={onClose}>
          ×
        </button>
        <span className="eyebrow">Рабочая форма</span>
        <h2>{title}</h2>
        {children}
      </div>
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="ops-empty">{children}</div>;
}
