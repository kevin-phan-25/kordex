ARG KORDEX_GO_BUILDER_BASE=golang:1.26.11-bookworm
ARG KORDEX_RUNTIME_BASE=debian:bookworm-slim
FROM ${KORDEX_GO_BUILDER_BASE} AS build
WORKDIR /src
COPY api/ ./api/
COPY control-plane/go.mod control-plane/go.sum ./control-plane/
WORKDIR /src/control-plane
RUN GOWORK=off go mod download
COPY control-plane/ ./
RUN GOWORK=off CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/kordex ./cmd/kordex
RUN GOWORK=off CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/kordex-scheduler ./cmd/kordex-scheduler
RUN GOWORK=off CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/kordex-audit-verify ./cmd/kordex-audit-verify
FROM ${KORDEX_RUNTIME_BASE}
COPY --from=build /out/kordex /kordex
COPY --from=build /out/kordex-scheduler /kordex-scheduler
COPY --from=build /out/kordex-audit-verify /kordex-audit-verify
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/kordex"]
