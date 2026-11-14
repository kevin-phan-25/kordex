FROM golang:1.26.11-bookworm AS build
WORKDIR /src
COPY api/ ./api/
COPY agent/go.mod agent/go.sum ./agent/
WORKDIR /src/agent
RUN GOWORK=off go mod download
COPY agent/ ./
RUN GOWORK=off CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/kordex-agent ./cmd/kordex-agent
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/kordex-agent /kordex-agent
USER 65532:65532
ENTRYPOINT ["/kordex-agent"]
