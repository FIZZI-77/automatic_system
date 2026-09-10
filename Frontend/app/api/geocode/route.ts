type NominatimResult = {
  place_id: number;
  display_name: string;
  lat: string;
  lon: string;
};

const geocoderURL = (process.env.NOMINATIM_URL || "https://nominatim.openstreetmap.org")
  .replace(/\/$/, "");

export async function GET(request: Request) {
  const query = new URL(request.url).searchParams.get("q")?.trim();
  if (!query || query.length < 3) {
    return Response.json({ suggestions: [] });
  }

  const url = new URL(`${geocoderURL}/search`);
  const parameters = {
    format: "jsonv2",
    addressdetails: "1",
    limit: "6",
    countrycodes: "ru",
    "accept-language": "ru",
    q: query,
  };
  Object.entries(parameters).forEach(([key, value]) => url.searchParams.set(key, value));

  try {
    const response = await fetch(url, {
      headers: { "User-Agent": "automatic-city-services/1.0" },
      signal: AbortSignal.timeout(5000),
    });
    if (!response.ok) {
      throw new Error(`geocoder returned ${response.status}`);
    }

    const results = await response.json() as NominatimResult[];
    return Response.json({
      suggestions: results.map((result) => ({
        id: String(result.place_id),
        address: result.display_name,
        latitude: Number(result.lat),
        longitude: Number(result.lon),
      })),
    });
  } catch {
    return Response.json(
      { error: "Сервис поиска адресов временно недоступен" },
      { status: 503 },
    );
  }
}
