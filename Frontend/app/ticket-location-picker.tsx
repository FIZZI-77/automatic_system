"use client";

import { useEffect, useRef, useState } from "react";
import "leaflet/dist/leaflet.css";

export type TicketLocation = {
  address: string;
  latitude: number;
  longitude: number;
};

type Suggestion = TicketLocation & { id: string };
type Props = {
  value?: TicketLocation;
  onChange: (location: TicketLocation) => void;
};

const defaultLocation: TicketLocation = {
  address: "Москва",
  latitude: 55.751244,
  longitude: 37.618423,
};

export function TicketLocationPicker({ value, onChange }: Props) {
  const mapRoot = useRef<HTMLDivElement>(null);
  const [mode, setMode] = useState<"address" | "map">("address");
  const [query, setQuery] = useState(value?.address || "");
  const [suggestions, setSuggestions] = useState<Suggestion[]>([]);
  const [searching, setSearching] = useState(false);

  useEffect(() => {
    if (mode !== "address" || query.trim().length < 3 || query === value?.address) {
      return;
    }

    const controller = new AbortController();
    const timer = window.setTimeout(async () => {
      setSearching(true);
      try {
        const response = await fetch(`/api/geocode?q=${encodeURIComponent(query)}`, {
          signal: controller.signal,
        });
        const payload = await response.json() as { suggestions?: Suggestion[] };
        setSuggestions(response.ok ? payload.suggestions || [] : []);
      } catch {
        if (!controller.signal.aborted) setSuggestions([]);
      } finally {
        if (!controller.signal.aborted) setSearching(false);
      }
    }, 350);

    return () => {
      window.clearTimeout(timer);
      controller.abort();
    };
  }, [mode, query, value?.address]);

  useEffect(() => {
    if (mode !== "map" || !mapRoot.current) return;

    let disposed = false;
    let map: import("leaflet").Map | undefined;
    void import("leaflet").then((leaflet) => {
      if (disposed || !mapRoot.current) return;

      const location = value || defaultLocation;
      map = leaflet.map(mapRoot.current).setView([location.latitude, location.longitude], 13);
      leaflet.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
        attribution: "© OpenStreetMap contributors",
        maxZoom: 19,
      }).addTo(map);

      const marker = leaflet.marker([location.latitude, location.longitude]).addTo(map);
      map.on("click", (event: import("leaflet").LeafletMouseEvent) => {
        marker.setLatLng(event.latlng);
        const next = {
          address: `Точка на карте: ${event.latlng.lat.toFixed(6)}, ${event.latlng.lng.toFixed(6)}`,
          latitude: event.latlng.lat,
          longitude: event.latlng.lng,
        };
        setQuery(next.address);
        onChange(next);
      });
    });

    return () => {
      disposed = true;
      map?.remove();
    };
  }, [mode, onChange, value]);

  function select(suggestion: Suggestion) {
    const next = {
      address: suggestion.address,
      latitude: suggestion.latitude,
      longitude: suggestion.longitude,
    };
    setQuery(next.address);
    setSuggestions([]);
    onChange(next);
  }

  return (
    <div className="ticket-location wide">
      <div className="location-mode" role="group" aria-label="Способ выбора места">
        <button type="button" className={mode === "address" ? "active" : ""} onClick={() => { setSuggestions([]); setMode("address"); }}>Найти адрес</button>
        <button type="button" className={mode === "map" ? "active" : ""} onClick={() => { setSuggestions([]); setMode("map"); }}>Указать на карте</button>
      </div>
      {mode === "address" ? (
        <label>Адрес
          <input value={query} onChange={(event) => { setQuery(event.target.value); setSuggestions([]); }} placeholder="Начните вводить улицу и дом" autoComplete="off" />
          {searching && <small>Ищем адрес…</small>}
          {suggestions.length > 0 && <div className="address-suggestions">
            {suggestions.map((suggestion) => <button type="button" key={suggestion.id} onClick={() => select(suggestion)}>{suggestion.address}</button>)}
          </div>}
        </label>
      ) : <><p>Нажмите на нужное место. Координаты сохранятся автоматически.</p><div className="ticket-location-map" ref={mapRoot} /></>}
      {value && <div className="selected-location"><b>Выбрано:</b> {value.address}</div>}
    </div>
  );
}
