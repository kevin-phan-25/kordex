MODULES := api control-plane agent operator
.PHONY: build test integration vet fmt contract
build:
	mkdir -p bin
	go build -trimpath -o bin/kordex ./control-plane/cmd/kordex
	go build -trimpath -o bin/kordex-scheduler ./control-plane/cmd/kordex-scheduler
	go build -trimpath -o bin/kordex-agent ./agent/cmd/kordex-agent
	go build -trimpath -o bin/kordex-operator ./operator/cmd/kordex-operator
	go build -trimpath -o bin/kordex-keygen ./api/cmd/kordex-keygen
	go build -trimpath -o bin/kordex-audit-verify ./control-plane/cmd/kordex-audit-verify
	go build -trimpath -o bin/kordex-audit-sign ./control-plane/cmd/kordex-audit-sign
	go build -trimpath -o bin/kordex-security-audit-export ./control-plane/cmd/kordex-security-audit-export
test:
	go test ./api/... ./control-plane/... ./agent/... ./operator/... ./integrations/...
	bash scripts/test-backup-postgres.sh
	bash scripts/test-restore-drill.sh
	bash scripts/test-export-audit.sh
	python3 -m unittest discover -s tests/infrastructure -v
	python3 -m unittest scripts.test_validate_image_sbom scripts.test_create_image_sbom_manifest -v
	python3 -m unittest scripts.test_container_base_lock -v
	python3 -m unittest scripts.test_release_image_workflow -v
	python3 -m unittest scripts.test_kyverno_image_policy -v
integration:
	@test -n "$$KORDEX_TEST_DATABASE_URL" || (echo 'Set KORDEX_TEST_DATABASE_URL to a disposable database'; exit 1)
	go test -count=1 ./api/... ./control-plane/... ./agent/... ./operator/... ./integrations/...
vet:
	go vet ./api/... ./control-plane/... ./agent/... ./operator/... ./integrations/...
fmt:
	gofmt -w api control-plane agent operator integrations
contract:
	python3 scripts/check-openapi.py
	go test ./control-plane/internal/httpapi -run Contract

.PHONY: generate envtest simulate
simulate:
	go run ./control-plane/cmd/kordex-simulate -nodes 4000 -clusters 100

.PHONY: offline-bundle
offline-bundle:
	@test -n "$$KORDEX_BUNDLE_VERSION" || (echo 'Set KORDEX_BUNDLE_VERSION'; exit 1)
	@test -n "$$KORDEX_BUNDLE_OUTPUT" || (echo 'Set KORDEX_BUNDLE_OUTPUT'; exit 1)
	./scripts/build-offline-bundle.sh "$$KORDEX_BUNDLE_VERSION" "$$KORDEX_BUNDLE_OUTPUT"

.PHONY: generate envtest
generate:
	go run sigs.k8s.io/controller-tools/cmd/controller-gen@v0.23.0 object crd paths=./api/operations/... output:crd:artifacts:config=operator/config/crd
	cp operator/config/crd/*.yaml deployments/helm/kordex-operator/crds/
	cp operator/config/crd/*.yaml deployments/kustomize/base/crds/
envtest:
	@test -n "$$KUBEBUILDER_ASSETS" || (echo 'Set KUBEBUILDER_ASSETS using setup-envtest'; exit 1)
	KORDEX_REQUIRE_ENVTEST=true go test -count=1 ./operator/internal/controller
