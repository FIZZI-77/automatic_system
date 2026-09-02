"use client";

import { useEffect, useRef, useState } from "react";
import "leaflet/dist/leaflet.css";
import { api, config, type Session, type Ticket } from "./api";

type Asset = {
  id: string;
  external_id?: string;
  serial_number?: string;
  name: string;
  address?: string;
  geometry_geo_json?: string;
};

type Mode = "map" | "number" | "qr";
type BarcodeDetectorInstance = { detect(source: ImageBitmapSource): Promise<Array<{ rawValue?: string }>> };
type BarcodeDetectorConstructor = new (options: { formats: string[] }) => BarcodeDetectorInstance;

export function TicketAssetPicker({ ticket, session, demo, onUpdate, onNotice }: {
  ticket: Ticket;
  session: Session;
  demo: boolean;
  onUpdate: (ticket: Ticket) => void;
  onNotice: (text: string) => void;
}) {
  const [mode, setMode] = useState<Mode>("map");
  const [assets, setAssets] = useState<Asset[]>([]);
  const [query, setQuery] = useState("");
  const [busy, setBusy] = useState(false);
  const [scanning, setScanning] = useState(false);
  const mapRoot = useRef<HTMLDivElement>(null);
  const videoRef = useRef<HTMLVideoElement>(null);
  const streamRef = useRef<MediaStream | null>(null);

  useEffect(() => () => streamRef.current?.getTracks().forEach(track => track.stop()), []);

  useEffect(() => {
    if (mode !== "map" || !mapRoot.current || assets.length === 0) return;
    let disposed = false;
    let map: import("leaflet").Map | undefined;
    void import("leaflet").then(leaflet => {
      if (disposed || !mapRoot.current) return;
      const points = assets.map(asset => ({ asset, point: assetPoint(asset) })).filter((item): item is { asset: Asset; point: [number, number] } => Boolean(item.point));
      if (points.length === 0) return;
      map = leaflet.map(mapRoot.current).setView(points[0].point, 15);
      leaflet.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", { attribution: "© OpenStreetMap contributors", maxZoom: 19 }).addTo(map);
      const bounds: [number, number][] = [];
      for (const item of points) {
        bounds.push(item.point);
        leaflet.marker(item.point).addTo(map).bindTooltip(item.asset.name).on("click", () => void attach(item.asset));
      }
      if (bounds.length > 1) map.fitBounds(bounds, { padding: [24, 24] });
    });
    return () => { disposed = true; map?.remove(); };
  // Recreating the map is intentionally driven only by its data and active tab.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [assets, mode]);

  async function attach(asset: Asset) {
    setBusy(true);
    try {
      let updated = { ...ticket, asset_id: asset.id };
      if (!demo) {
        const result = await api<{ ticket: Ticket }>(config.endpoints.ticketsUpdate, { ticket_id: ticket.id, asset_id: asset.id, updated_by: session.user?.user_id }, "POST", session.accessToken);
        updated = result.ticket;
      }
      onUpdate(updated);
      onNotice(`Объект «${asset.name}» привязан к заявке`);
    } catch (error) {
      onNotice(error instanceof Error ? error.message : "Не удалось привязать объект");
    } finally { setBusy(false); }
  }

  async function findByNumber() {
    const needle = query.trim().toLocaleLowerCase("ru-RU");
    if (!needle) return;
    setBusy(true);
    try {
      const result = await api<{ asset: Asset }>(config.endpoints.assetsResolve, { identifier: needle }, "POST", session.accessToken);
      setAssets([result.asset]);
    } catch (error) { onNotice(error instanceof Error ? error.message : "Не удалось выполнить поиск"); }
    finally { setBusy(false); }
  }

  function findNearby() {
    if (!navigator.geolocation) { onNotice("Браузер не поддерживает геолокацию"); return; }
    setBusy(true);
    navigator.geolocation.getCurrentPosition(async position => {
      try {
        const result = await api<{ assets: Asset[] }>(config.endpoints.assetsNearby, { latitude: position.coords.latitude, longitude: position.coords.longitude, radius_meters: 1000, limit: 100 }, "POST", session.accessToken);
        setAssets(result.assets || []);
        if (!result.assets?.length) onNotice("В радиусе километра объекты не найдены");
      } catch (error) { onNotice(error instanceof Error ? error.message : "Не удалось загрузить объекты рядом"); }
      finally { setBusy(false); }
    }, () => { setBusy(false); onNotice("Разрешите доступ к геопозиции"); }, { enableHighAccuracy: true, timeout: 10000 });
  }

  async function startQR() {
    const Detector = (window as Window & { BarcodeDetector?: BarcodeDetectorConstructor }).BarcodeDetector;
    if (!Detector || !navigator.mediaDevices?.getUserMedia) { onNotice("QR-сканирование не поддерживается этим браузером"); return; }
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: { ideal: "environment" } }, audio: false });
      streamRef.current = stream;
      if (videoRef.current) { videoRef.current.srcObject = stream; await videoRef.current.play(); }
      setScanning(true);
      const detector = new Detector({ formats: ["qr_code"] });
      const timer = window.setInterval(async () => {
        if (!videoRef.current || videoRef.current.readyState < 2) return;
        const raw = (await detector.detect(videoRef.current))[0]?.rawValue?.trim();
        if (!raw) return;
        window.clearInterval(timer); stopQR(); await resolveQR(raw);
      }, 350);
      window.setTimeout(() => { window.clearInterval(timer); if (streamRef.current) { stopQR(); onNotice("QR-код не распознан"); } }, 30000);
    } catch { stopQR(); onNotice("Не удалось открыть камеру"); }
  }

  function stopQR() { streamRef.current?.getTracks().forEach(track => track.stop()); streamRef.current = null; setScanning(false); }

  async function resolveQR(raw: string) {
    const id = qrAssetID(raw);
    try {
      const result = await api<{ asset: Asset }>(config.endpoints.assetsGet, { asset_id: id }, "POST", session.accessToken);
      await attach(result.asset);
    } catch { onNotice("QR-код не содержит действительный asset_id"); }
  }

  return <section className="ticket-asset-linker">
    <div className="asset-linker-head"><div><h3>Объект работ</h3><p>{ticket.asset_id ? `Привязан: ${ticket.asset_id}` : "Выберите фактический объект перед выполнением работ"}</p></div></div>
    <div className="location-mode" role="group" aria-label="Способ выбора объекта">
      <button type="button" className={mode === "map" ? "active" : ""} onClick={() => setMode("map")}>На карте</button>
      <button type="button" className={mode === "number" ? "active" : ""} onClick={() => setMode("number")}>По номеру</button>
      <button type="button" className={mode === "qr" ? "active" : ""} onClick={() => setMode("qr")}>QR-код</button>
    </div>
    {mode === "map" && <div><button type="button" disabled={busy} onClick={findNearby}>Показать объекты рядом</button>{assets.length > 0 && <div className="asset-picker-map" ref={mapRoot}/>}</div>}
    {mode === "number" && <div className="asset-number-search"><input value={query} onChange={event => setQuery(event.target.value)} placeholder="Серийный или инвентарный номер"/><button type="button" disabled={busy} onClick={findByNumber}>Найти</button></div>}
    {mode === "qr" && <div className="asset-qr"><video ref={videoRef} muted playsInline/><button type="button" disabled={busy} onClick={scanning ? stopQR : startQR}>{scanning ? "Остановить камеру" : "Сканировать QR"}</button></div>}
    {mode !== "map" && assets.length > 0 && <div className="asset-suggestions">{assets.map(asset => <button type="button" key={asset.id} disabled={busy} onClick={() => void attach(asset)}><b>{asset.name}</b><span>{asset.serial_number || asset.external_id || asset.id}</span></button>)}</div>}
  </section>;
}

function assetPoint(asset: Asset): [number, number] | undefined {
  if (!asset.geometry_geo_json) return undefined;
  try {
    const geometry = JSON.parse(asset.geometry_geo_json) as { type?: string; coordinates?: [number, number] };
    if (geometry.type !== "Point" || !geometry.coordinates) return undefined;
    return [geometry.coordinates[1], geometry.coordinates[0]];
  } catch { return undefined; }
}

function qrAssetID(raw: string): string {
  try { const url = new URL(raw); return url.searchParams.get("asset_id") || url.pathname.split("/").filter(Boolean).at(-1) || raw; }
  catch { return raw.replace(/^asset:/i, ""); }
}
