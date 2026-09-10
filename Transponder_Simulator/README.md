# Transponder Simulator

Эмулирует автомобильный GPS-транспондер и последовательно отправляет точки маршрута.

Пока `TARGET_URL` пустой, события печатаются в stdout. После появления Location Service
укажите URL его HTTP endpoint, например:

```env
TARGET_URL=http://location-service:8080/v1/positions
```

Локальный запуск:

```powershell
Copy-Item .env.example .env
Get-Content .env | ForEach-Object {
    if ($_ -match '^([^#][^=]*)=(.*)$') {
        [Environment]::SetEnvironmentVariable($matches[1], $matches[2], 'Process')
    }
}
go run ./cmd/simulator
```

Docker:

```powershell
docker build -t transponder-simulator .
docker run --env-file .env transponder-simulator
```

Маршрут задаётся JSON-файлом:

```json
{
  "name": "demo",
  "points": [
    {"latitude": 55.7558, "longitude": 37.6173, "speed_kmh": 20},
    {"latitude": 55.7564, "longitude": 37.6191, "speed_kmh": 35}
  ]
}
```

HTTP-запрос содержит envelope `VehiclePositionUpdated`. При непустом
`TRANSPONDER_API_KEY` также отправляется заголовок `X-Transponder-Key`.
