import http from "node:http";

const listenPort = Number(process.env.E2E_INGRESS_PROXY_PORT || "18081");
const targetPort = Number(process.env.E2E_INGRESS_TARGET_PORT || "80");
const targetHost = process.env.E2E_INGRESS_HOST || "tunnel.automatic-system.internal";
const requestsPerAddress = 8;
let requestCount = 0;

const server = http.createServer((request, response) => {
  const addressSuffix = 10 + Math.floor(requestCount++ / requestsPerAddress) % 200;
  const headers = {
    ...request.headers,
    host: targetHost,
    "x-forwarded-for": `198.51.100.${addressSuffix}`,
  };
  const upstream = http.request({
    host: "127.0.0.1",
    port: targetPort,
    method: request.method,
    path: request.url,
    headers,
  }, (upstreamResponse) => {
    response.writeHead(upstreamResponse.statusCode || 502, upstreamResponse.headers);
    upstreamResponse.pipe(response);
  });

  upstream.on("error", (error) => {
    if (!response.headersSent) response.writeHead(502, { "content-type": "text/plain; charset=utf-8" });
    response.end(`Istio ingress is unavailable: ${error.message}`);
  });
  request.pipe(upstream);
});

server.listen(listenPort, "127.0.0.1", () => {
  process.stdout.write(`E2E ingress proxy listening on http://127.0.0.1:${listenPort}\n`);
});

function shutdown() {
  server.close(() => process.exit(0));
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
