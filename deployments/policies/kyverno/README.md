# Kordex image signature admission policy

This opt-in ClusterPolicy requires digest-pinned Kordex images and verifies
their Cosign keyless signature against the GitHub Actions OIDC issuer and the
release workflow's exact repository, workflow path, tag ref, and SemVer shape.
It covers the four first-party GHCR repositories used by the release workflow.
Kyverno applies Pod-matching policies to supported Pod controllers as well.

## Prerequisites and install

Install and qualify Kyverno 1.18.0 or a compatible version with the
`kyverno.io/v1` ClusterPolicy image-verification API before applying this
policy. Keep Kyverno's admission webhook configured with `failurePolicy: Fail`.
The policy itself also sets fail-closed webhook handling and `failureAction:
Enforce`. Kyverno must be able to read image manifests/signatures and reach the
Sigstore Rekor service. Configure registry credentials in Kyverno if the GHCR
packages are private. Private mirrors do not match this policy and need their
own verified signature-transfer and policy review.

Install only after the Kyverno CRDs and admission webhooks are ready:

```sh
kubectl apply -k deployments/policies/kyverno
kubectl get clusterpolicy kordex-release-images
```

Remove with:

```sh
kubectl delete -k deployments/policies/kyverno
```

This policy is separate from the Kordex Helm and Kustomize application
installations because it requires a cluster-wide Kyverno installation and
cluster-scoped permissions. It is not included in either default installation
path. The normal deployment profiles continue to require image digests, but do
not verify signatures unless this policy is installed.

The policy verifies image signatures and requires digest references. It does
not yet enforce provenance or SBOM attestations, and it has not been tested
against a published Kordex release or a live Kyverno admission controller.
Do not treat the local Kyverno CLI denial simulation as admission qualification.
Run it with `bash scripts/test-kyverno-image-policy.sh`; the test downloads the
Kyverno CLI v1.18.0 release and checks its SHA-256 before use.
