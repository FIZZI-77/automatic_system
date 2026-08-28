FROM node:22-alpine AS dependencies
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm install --ignore-scripts --no-audit --no-fund

FROM node:22-alpine AS builder
WORKDIR /app
COPY --from=dependencies /app/node_modules ./node_modules
COPY . .
ARG NEXT_PUBLIC_API_BASE_URL=https://api.city.localhost
ARG NEXT_PUBLIC_NOTIFICATIONS_WS_URL=wss://api.city.localhost/notifications/ws
ARG NEXT_PUBLIC_SITE_URL=https://city.localhost
ARG NEXT_PUBLIC_YANDEX_MAPS_API_URL=https://api-maps.yandex.ru/v3/
ARG NEXT_PUBLIC_YANDEX_MAPS_API_KEY
ARG NEXT_PUBLIC_YANDEX_MAPS_LANG=ru_RU
ARG NEXT_PUBLIC_YANDEX_MAPS_EMBED_URL=https://yandex.ru/map-widget/v1/?ll=37.618423%2C55.751244&z=12
ARG NEXT_PUBLIC_OPEN_MAP_TILE_URL=https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png
ARG NEXT_PUBLIC_OPEN_MAP_ATTRIBUTION=OpenStreetMap contributors
ARG NEXT_PUBLIC_HOT_MAP_TILE_URL=https://{s}.tile.openstreetmap.fr/hot/{z}/{x}/{y}.png
ARG NEXT_PUBLIC_TOPO_MAP_TILE_URL=https://{s}.tile.opentopomap.org/{z}/{x}/{y}.png
ENV NEXT_PUBLIC_API_BASE_URL=$NEXT_PUBLIC_API_BASE_URL \
    NEXT_PUBLIC_NOTIFICATIONS_WS_URL=$NEXT_PUBLIC_NOTIFICATIONS_WS_URL \
    NEXT_PUBLIC_SITE_URL=$NEXT_PUBLIC_SITE_URL \
    NEXT_PUBLIC_YANDEX_MAPS_API_URL=$NEXT_PUBLIC_YANDEX_MAPS_API_URL \
    NEXT_PUBLIC_YANDEX_MAPS_API_KEY=$NEXT_PUBLIC_YANDEX_MAPS_API_KEY \
    NEXT_PUBLIC_YANDEX_MAPS_LANG=$NEXT_PUBLIC_YANDEX_MAPS_LANG \
    NEXT_PUBLIC_YANDEX_MAPS_EMBED_URL=$NEXT_PUBLIC_YANDEX_MAPS_EMBED_URL \
    NEXT_PUBLIC_OPEN_MAP_TILE_URL=$NEXT_PUBLIC_OPEN_MAP_TILE_URL \
    NEXT_PUBLIC_OPEN_MAP_ATTRIBUTION=$NEXT_PUBLIC_OPEN_MAP_ATTRIBUTION \
    NEXT_PUBLIC_HOT_MAP_TILE_URL=$NEXT_PUBLIC_HOT_MAP_TILE_URL \
    NEXT_PUBLIC_TOPO_MAP_TILE_URL=$NEXT_PUBLIC_TOPO_MAP_TILE_URL
RUN npm run build

FROM node:22-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production HOST=0.0.0.0 PORT=3000
COPY --from=builder /app/package.json /app/package-lock.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/public ./public
COPY --from=builder /app/.openai ./.openai
EXPOSE 3000
USER node
CMD ["npm", "run", "start", "--", "--host", "0.0.0.0"]
