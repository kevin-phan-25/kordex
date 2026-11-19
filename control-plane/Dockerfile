ARG KORDEX_GO_BUILDER_BASE=golang:1.26.11-bookworm@sha256:dc40a13b61304647ed7e5d581d246b86413dfc29d63c6d018310feb93cd98fc0
ARG KORDEX_RUNTIME_BASE=debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
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
RUN GOWORK=off CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/kordex-audit-sign ./cmd/kordex-audit-sign
RUN GOWORK=off CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/kordex-security-audit-export ./cmd/kordex-security-audit-export
FROM ${KORDEX_RUNTIME_BASE}
COPY --from=build /out/kordex /kordex
COPY --from=build /out/kordex-scheduler /kordex-scheduler
COPY --from=build /out/kordex-audit-verify /kordex-audit-verify
COPY --from=build /out/kordex-audit-sign /kordex-audit-sign
COPY --from=build /out/kordex-security-audit-export /kordex-security-audit-export
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
USER 65532:65532
EXPOSE 8080 8081
ENTRYPOINT ["/kordex"]
