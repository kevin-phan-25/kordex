MODULES := api control-plane agent operator
.PHONY: build test integration vet fmt contract
build:
	mkdir -p bin
	go build -trimpath -o bin/kordex ./control-plane/cmd/kordex
	go build -trimpath -o bin/kordex-scheduler ./control-plane/cmd/kordex-scheduler
	go build -trimpath -o bin/kordex-agent ./agent/cmd/kordex-agent
	go build -trimpath -o bin/kordex-operator ./operator/cmd/kordex-operator
	go build -trimpath -o bin/kordex-keygen ./api/cmd/kordex-keygen
test:
	go test ./api/... ./control-plane/... ./agent/... ./operator/...
integration:
	@test -n "$$KORDEX_TEST_DATABASE_URL" || (echo 'Set KORDEX_TEST_DATABASE_URL to a disposable database'; exit 1)
	go test -count=1 ./api/... ./control-plane/... ./agent/... ./operator/...
vet:
	go vet ./api/... ./control-plane/... ./agent/... ./operator/...
fmt:
	gofmt -w api control-plane agent operator
contract:
	python3 scripts/check-openapi.py
	go test ./control-plane/internal/httpapi -run Contract

.PHONY: generate envtest simulate
simulate:
	go run ./control-plane/cmd/kordex-simulate -nodes 4000 -clusters 100

.PHONY: generate envtest
generate:
	go run sigs.k8s.io/controller-tools/cmd/controller-gen@v0.23.0 object crd paths=./api/operations/... output:crd:artifacts:config=operator/config/crd
	cp operator/config/crd/*.yaml deployments/helm/kordex-operator/crds/
envtest:
	@test -n "$$KUBEBUILDER_ASSETS" || (echo 'Set KUBEBUILDER_ASSETS using setup-envtest'; exit 1)
	KORDEX_REQUIRE_ENVTEST=true go test -count=1 ./operator/internal/controller
