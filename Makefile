.PHONY: build test integration vet fmt contract
build:
	mkdir -p bin
	cd control-plane && go build -trimpath -o ../bin/kordex ./cmd/kordex
test:
	cd control-plane && go test ./...
integration:
	@test -n "$$KORDEX_TEST_DATABASE_URL" || (echo 'Set KORDEX_TEST_DATABASE_URL to a disposable database'; exit 1)
	cd control-plane && go test -count=1 ./...
vet:
	cd control-plane && go vet ./...
fmt:
	cd control-plane && go fmt ./...
contract:
	python3 scripts/check-openapi.py
