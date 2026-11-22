# Pinned controller-gen toolchain

The generator is pinned in this directory's `go.mod` to `sigs.k8s.io/controller-tools v0.23.0`; `go.sum` records its module checksums. This is the version already represented by the generated CRD annotations and is compatible with the repository's Kubernetes API/controller-runtime dependency line.

`make generate` is an offline operation. It locates `controller-gen` at `$(go env GOPATH)/bin/controller-gen` (or the path selected with `CONTROLLER_GEN`), checks that `controller-gen --version` is exactly `Version: v0.23.0`, and then regenerates API deep-copy code and CRDs. If the binary is absent or mismatched, generation stops without downloading or changing anything. Set `CONTROLLER_GEN` to a particular executable when it is installed elsewhere.

## Explicit acquisition

On a connected, approved build workstation, acquire only the pinned module using the checksums in this module:

```sh
make install-controller-gen
"$(go env GOPATH)/bin/controller-gen" --version
```

The install target uses `GOWORK=off`, the pinned tool module, `-mod=readonly`, and runs `go mod verify` after installation. Go verifies module content against `go.sum` and the configured Go checksum database when an entry is first acquired. Review the exact version and module checksums with the software supply-chain process. No standalone binary checksum or provenance claim is fabricated here.

For a disconnected builder, provide the pinned executable through the organization's approved software-transfer process, verify its version before use, and set `CONTROLLER_GEN` to its path. Alternatively, pre-stage the exact modules and their sum-verified content in an approved internal Go module proxy/cache, then run `make install-controller-gen` with `GOPROXY` set to that internal source, `GOSUMDB=off` only when all required sums are already in the checked-in `go.sum`, and `GOTOOLCHAIN=local`. The generation command itself needs no Go module or network access once the exact binary is present.

## Reproducibility checks

```sh
bash scripts/test-controller-gen-toolchain.sh
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local make generate
git diff --exit-code -- api/operations operator/config/crd \
  deployments/helm/kordex-operator/crds deployments/kustomize/base/crds
```

CI explicitly installs the pinned generator, tests the version guard, runs generation with Go module/network lookup disabled, and fails if generated files differ from the checkout. Run generation twice locally and compare the generated-file diff to confirm idempotence. Generated API changes must originate in the API types and markers; do not edit output to silence the check.
