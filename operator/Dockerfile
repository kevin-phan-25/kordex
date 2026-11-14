FROM golang:1.26.11-bookworm AS build
WORKDIR /src
COPY api/ ./api/
COPY operator/go.mod operator/go.sum ./operator/
WORKDIR /src/operator
RUN GOWORK=off go mod download
COPY operator/ ./
RUN GOWORK=off CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/kordex-operator ./cmd/kordex-operator
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/kordex-operator /kordex-operator
USER 65532:65532
EXPOSE 8081
ENTRYPOINT ["/kordex-operator"]
