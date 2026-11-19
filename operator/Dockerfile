ARG KORDEX_GO_BUILDER_BASE=golang:1.26.11-bookworm@sha256:dc40a13b61304647ed7e5d581d246b86413dfc29d63c6d018310feb93cd98fc0
ARG KORDEX_RUNTIME_BASE=debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
FROM ${KORDEX_GO_BUILDER_BASE} AS build
WORKDIR /src
COPY api/ ./api/
COPY operator/go.mod operator/go.sum ./operator/
WORKDIR /src/operator
RUN GOWORK=off go mod download
COPY operator/ ./
RUN GOWORK=off CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/kordex-operator ./cmd/kordex-operator
FROM ${KORDEX_RUNTIME_BASE}
COPY --from=build /out/kordex-operator /kordex-operator
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
USER 65532:65532
EXPOSE 8081
ENTRYPOINT ["/kordex-operator"]
