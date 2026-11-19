ARG KORDEX_NODE_BASE=node:22-bookworm-slim@sha256:e9f565d32859f0cbfb52125eafe8be39390f24dac302dc3cdf566e8ba3ab21ee
ARG KORDEX_NODE_RUNTIME_BASE=node:22-bookworm-slim@sha256:e9f565d32859f0cbfb52125eafe8be39390f24dac302dc3cdf566e8ba3ab21ee
FROM ${KORDEX_NODE_BASE} AS deps
WORKDIR /app
COPY dashboard/package.json dashboard/package-lock.json ./
RUN npm ci
FROM ${KORDEX_NODE_BASE} AS build
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
COPY --from=deps /app/node_modules ./node_modules
COPY dashboard/ ./
RUN npm run build
FROM ${KORDEX_NODE_RUNTIME_BASE} AS runtime
WORKDIR /app
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 PORT=3000 HOSTNAME=0.0.0.0
COPY --from=build --chown=65532:65532 /app/public ./public
COPY --from=build --chown=65532:65532 /app/.next/standalone ./
COPY --from=build --chown=65532:65532 /app/.next/static ./.next/static
EXPOSE 3000
USER 65532:65532
CMD ["server.js"]
