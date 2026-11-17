ARG KORDEX_GO_BUILDER_BASE=golang:1.26.11-bookworm
ARG KORDEX_RUNTIME_BASE=debian:bookworm-slim
FROM ${KORDEX_GO_BUILDER_BASE} AS build
WORKDIR /src
COPY api/ ./api/
COPY agent/go.mod agent/go.sum ./agent/
WORKDIR /src/agent
RUN GOWORK=off go mod download
COPY agent/ ./
RUN GOWORK=off CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/kordex-agent ./cmd/kordex-agent
FROM ${KORDEX_RUNTIME_BASE}
COPY --from=build /out/kordex-agent /kordex-agent
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
USER 65532:65532
ENTRYPOINT ["/kordex-agent"]
