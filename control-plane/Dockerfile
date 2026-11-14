FROM golang:1.26.11-bookworm AS build
WORKDIR /src
COPY api/ ./api/
COPY control-plane/go.mod control-plane/go.sum ./control-plane/
WORKDIR /src/control-plane
RUN GOWORK=off go mod download
COPY control-plane/ ./
RUN GOWORK=off CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/kordex ./cmd/kordex
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/kordex /kordex
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/kordex"]
