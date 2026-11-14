MODULES := api control-plane agent
.PHONY: build test integration vet fmt contract
build:
	mkdir -p bin
	go build -trimpath -o bin/kordex ./control-plane/cmd/kordex
	go build -trimpath -o bin/kordex-agent ./agent/cmd/kordex-agent
test:
	go test ./api/... ./control-plane/... ./agent/...
integration:
	@test -n "$$KORDEX_TEST_DATABASE_URL" || (echo 'Set KORDEX_TEST_DATABASE_URL to a disposable database'; exit 1)
	go test -count=1 ./api/... ./control-plane/... ./agent/...
vet:
	go vet ./api/... ./control-plane/... ./agent/...
fmt:
	gofmt -w api/protocol control-plane agent
contract:
	python3 scripts/check-openapi.py
	go test ./control-plane/internal/httpapi -run Contract
