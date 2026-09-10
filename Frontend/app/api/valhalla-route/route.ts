type Point = { latitude: number; longitude: number };

const valhallaUrl = (process.env.VALHALLA_URL || "http://host.docker.internal:8002").replace(/\/$/, "");

function validPoint(value: unknown): value is Point {
  if (!value || typeof value !== "object") return false;
  const point = value as Point;
  return Number.isFinite(point.latitude) && Number.isFinite(point.longitude) &&
    Math.abs(point.latitude) <= 90 && Math.abs(point.longitude) <= 180;
}

function encodePolyline6(points: Point[]): string {
  let previousLatitude = 0;
  let previousLongitude = 0;
  let encoded = "";

  const encodeValue = (value: number) => {
    let shifted = value < 0 ? ~(value << 1) : value << 1;
    while (shifted >= 0x20) {
      encoded += String.fromCharCode((0x20 | (shifted & 0x1f)) + 63);
      shifted >>= 5;
    }
    encoded += String.fromCharCode(shifted + 63);
  };

  for (const point of points) {
    const latitude = Math.round(point.latitude * 1_000_000);
    const longitude = Math.round(point.longitude * 1_000_000);
    encodeValue(latitude - previousLatitude);
    encodeValue(longitude - previousLongitude);
    previousLatitude = latitude;
    previousLongitude = longitude;
  }

  return encoded;
}

function distanceMeters(origin: Point, destination: Point): number {
  const radians = (degrees: number) => degrees * Math.PI / 180;
  const latitudeDelta = radians(destination.latitude - origin.latitude);
  const longitudeDelta = radians(destination.longitude - origin.longitude);
  const originLatitude = radians(origin.latitude);
  const destinationLatitude = radians(destination.latitude);
  const haversine = Math.sin(latitudeDelta / 2) ** 2 +
    Math.cos(originLatitude) * Math.cos(destinationLatitude) * Math.sin(longitudeDelta / 2) ** 2;
  return Math.round(6_371_000 * 2 * Math.atan2(Math.sqrt(haversine), Math.sqrt(1 - haversine)));
}

function fallbackRoute(origin: Point, destination: Point) {
  const distance = distanceMeters(origin, destination);
  return Response.json({
    encoded_polylines: [encodePolyline6([origin, destination])],
    distance_meters: distance,
    duration_seconds: Math.round(distance / 8.33),
    engine: "direct-fallback",
  });
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
      return fallbackRoute(input.origin, input.destination);
    }
    return Response.json({
      encoded_polylines: shapes,
      distance_meters: Math.round((trip.summary?.length || 0) * 1000),
      duration_seconds: Math.round(trip.summary?.time || 0),
      engine: "valhalla",
    });
  } catch {
    return fallbackRoute(input.origin, input.destination);
  } finally {
    clearTimeout(timeout);
  }
}
