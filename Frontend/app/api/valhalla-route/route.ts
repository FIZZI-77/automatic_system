type Point = { latitude: number; longitude: number };

const valhallaUrl = (process.env.VALHALLA_URL || "http://host.docker.internal:8002").replace(/\/$/, "");

function validPoint(value: unknown): value is Point {
  if (!value || typeof value !== "object") return false;
  const point = value as Point;
  return Number.isFinite(point.latitude) && Number.isFinite(point.longitude) &&
    Math.abs(point.latitude) <= 90 && Math.abs(point.longitude) <= 180;
}

export async function POST(request: Request) {
  const input = await request.json().catch(() => null) as { origin?: Point; destination?: Point } | null;
  if (!validPoint(input?.origin) || !validPoint(input?.destination)) {
    return Response.json({ error: "Некорректные координаты маршрута" }, { status: 400 });
  }
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15_000);
  try {
    const response = await fetch(`${valhallaUrl}/route`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        locations: [
          { lat: input.origin.latitude, lon: input.origin.longitude, type: "break" },
          { lat: input.destination.latitude, lon: input.destination.longitude, type: "break" },
        ],
        costing: "auto",
        units: "kilometers",
        directions_options: { units: "kilometers", language: "ru-RU" },
      }),
      signal: controller.signal,
    });
    const payload = await response.json().catch(() => null) as {
      error?: string;
      trip?: { shape?: string; legs?: { shape?: string }[]; summary?: { length?: number; time?: number }; status_message?: string };
    } | null;
    const trip=payload?.trip;
    const shapes = trip?.shape
      ? [trip.shape]
      : (trip?.legs || []).map(leg => leg.shape).filter((shape): shape is string => Boolean(shape));
    if (!response.ok || !trip || !shapes.length) {
      return Response.json({ error: payload?.error || payload?.trip?.status_message || "Valhalla не построила маршрут" }, { status: 502 });
    }
    return Response.json({
      encoded_polylines: shapes,
      distance_meters: Math.round((trip.summary?.length || 0) * 1000),
      duration_seconds: Math.round(trip.summary?.time || 0),
      engine: "valhalla",
    });
  } catch (error) {
    const message = error instanceof Error && error.name === "AbortError"
      ? "Valhalla не ответила за 15 секунд"
      : "Valhalla недоступна";
    return Response.json({ error: message }, { status: 503 });
  } finally {
    clearTimeout(timeout);
  }
}
