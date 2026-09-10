const overpassUrl = process.env.OVERPASS_API_URL || "https://overpass-api.de/api/interpreter";

type OverpassElement = {
  type?: "node" | "way" | "relation";
  id: number;
  lat?: number;
  lon?: number;
  center?: { lat: number; lon: number };
  geometry?: { lat: number; lon: number }[];
  tags?: Record<string, string>;
};
type InfrastructureFeature = { id:string; category:string; name:string; kind:string; latitude?:number; longitude?:number; coordinates?:number[][]; address?:string; operator?:string; network?:string; ref?:string };

let cache: { expires: number; features: unknown[] } | null = null;

async function fetchOverpass(query: string) {
  const response = await fetch(overpassUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8", "User-Agent": "AutomaticCityServices/1.0" },
    body: new URLSearchParams({ data: query }),
  });
  if (!response.ok) throw new Error(`Overpass ${response.status}`);
  return response.json() as Promise<{ elements?: OverpassElement[] }>;
}

function category(tags: Record<string, string>) {
  if (tags.boundary === "administrative") return "districts";
  if (tags.highway && ["primary", "secondary", "tertiary", "primary_link", "secondary_link", "tertiary_link"].includes(tags.highway)) return "roads";
  if (tags.highway === "street_lamp") return "lighting";
  if (tags.highway === "traffic_signals") return "traffic";
  if (tags.highway === "bus_stop" || tags.public_transport || tags.railway) return "stops";
  if (tags.emergency === "fire_hydrant") return "utilities";
  if (tags.power) return "energy";
  if (tags.amenity === "bus_station") return "stops";
  if (["fire_station", "police", "hospital", "clinic"].includes(tags.amenity)) return "emergency";
  if (["drinking_water", "waste_disposal", "recycling"].includes(tags.amenity) || tags.man_made === "water_tower") return "utilities";
  return "social";
}

export async function GET() {
  if (cache && cache.expires > Date.now()) return Response.json({ features: cache.features, source: "OpenStreetMap" });
  const bbox = "55.70,37.48,55.84,37.76";
  const pointQuery = `[out:json][timeout:25];(
    node[highway="bus_stop"](${bbox});
    node[public_transport="platform"](${bbox});
    node[highway="street_lamp"](${bbox});
    node[highway="traffic_signals"](${bbox});
    node[emergency="fire_hydrant"](${bbox});
    nwr[amenity~"^(fire_station|police|hospital|clinic|school|kindergarten|bus_station|drinking_water|waste_disposal|recycling)$"](${bbox});
    nwr[public_transport~"^(station|stop_position)$"](${bbox});
    nwr[railway~"^(station|halt)$"](${bbox});
    nwr[power~"^(substation|plant|generator)$"](${bbox});
    nwr[man_made="water_tower"](${bbox});
  );out center 2500;`;
  const lineQuery = `[out:json][timeout:25];(
    way[boundary="administrative"](${bbox});
    way[highway~"^(primary|secondary|tertiary|primary_link|secondary_link|tertiary_link)$"](${bbox});
  );out geom 900;`;
  try {
    const [points, lines] = await Promise.all([fetchOverpass(pointQuery), fetchOverpass(lineQuery)]);
    const features:InfrastructureFeature[] = [...(points.elements || []), ...(lines.elements || [])].flatMap<InfrastructureFeature>(element => {
      const latitude = element.lat ?? element.center?.lat;
      const longitude = element.lon ?? element.center?.lon;
      const tags = element.tags || {};
      const featureCategory = category(tags);
      if (element.geometry?.length && ["roads", "districts"].includes(featureCategory)) {
        return [{ id: `osm-${element.type || "element"}-${element.id}`, coordinates: element.geometry.map(point => [point.lat, point.lon]), category: featureCategory, name: tags["name:ru"] || tags.name || (featureCategory === "roads" ? "Дорога" : "Граница округа"), kind: tags.highway || tags.boundary || "line" }];
      }
      if (latitude == null || longitude == null) return [];
      return [{
        id: `osm-${element.type || "element"}-${element.id}`,
        latitude,
        longitude,
        category: featureCategory,
        name: tags["name:ru"] || tags.name || tags.operator || (featureCategory === "stops" ? "Остановка общественного транспорта" : "Объект инфраструктуры"),
        kind: tags.amenity || tags.public_transport || tags.railway || tags.power || tags.man_made || "infrastructure",
        address: [tags["addr:street"],tags["addr:housenumber"]].filter(Boolean).join(", "),
        operator: tags.operator,
        network: tags.network,
        ref: tags.ref || tags.local_ref,
      }];
    });
    cache = { expires: Date.now() + 15 * 60_000, features };
    return Response.json({ features, source: "OpenStreetMap" }, { headers: { "Cache-Control": "public, max-age=900" } });
  } catch {
    return Response.json({ error: "Открытые данные инфраструктуры временно недоступны", features: [] }, { status: 503 });
  }
}
