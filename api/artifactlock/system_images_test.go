package artifactlock

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kordex.local/api/protocol"
)

type fixtureDescriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Platform    *ociPlatform      `json:"platform,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

type fixtureManifest struct {
	SchemaVersion int                 `json:"schemaVersion"`
	MediaType     string              `json:"mediaType"`
	Config        fixtureDescriptor   `json:"config"`
	Layers        []fixtureDescriptor `json:"layers"`
}

type fixtureIndex struct {
	SchemaVersion int                 `json:"schemaVersion"`
	MediaType     string              `json:"mediaType"`
	Manifests     []fixtureDescriptor `json:"manifests"`
}

func imageFixtureKey(t *testing.T) (ed25519.PrivateKey, []byte) {
	t.Helper()
	seed := sha256.Sum256([]byte("synthetic customer K3s image approval fixture; not production trust"))
	private := ed25519.NewKeyFromSeed(seed[:])
	public := private.Public().(ed25519.PublicKey)
	bundle, err := EncodeTrust(map[string]ed25519.PublicKey{protocol.KeyID(public): public})
	if err != nil {
		t.Fatal(err)
	}
	return private, bundle
}

func makeOCIImageBundle(t *testing.T, architecture string, omit, replace string, corruptLayer bool) string {
	t.Helper()
	blobs := map[string][]byte{}
	index := fixtureIndex{SchemaVersion: 2, MediaType: "application/vnd.oci.image.index.v1+json"}
	for i, original := range k3sSystemImageReferences {
		if original == omit {
			continue
		}
		ref := original
		if original == replace {
			ref = "docker.io/attacker/unexpected:v1"
		}
		config, err := json.Marshal(ociConfig{Architecture: architecture, OS: "linux"})
		if err != nil {
			t.Fatal(err)
		}
		layer := []byte("synthetic layer " + ref)
		configDescriptor := fixtureBlob(t, "application/vnd.oci.image.config.v1+json", config)
		layerDescriptor := fixtureBlob(t, "application/vnd.oci.image.layer.v1.tar", layer)
		blobs[strings.TrimPrefix(configDescriptor.Digest, "sha256:")] = config
		blobs[strings.TrimPrefix(layerDescriptor.Digest, "sha256:")] = layer
		manifest := fixtureManifest{SchemaVersion: 2, MediaType: "application/vnd.oci.image.manifest.v1+json", Config: configDescriptor, Layers: []fixtureDescriptor{layerDescriptor}}
		manifestBytes, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		manifestDescriptor := fixtureBlob(t, "application/vnd.oci.image.manifest.v1+json", manifestBytes)
		blobs[strings.TrimPrefix(manifestDescriptor.Digest, "sha256:")] = manifestBytes
		manifestDescriptor.Platform = &ociPlatform{OS: "linux", Architecture: "amd64"}
		manifestDescriptor.Annotations = map[string]string{"org.opencontainers.image.ref.name": ref}
		index.Manifests = append(index.Manifests, manifestDescriptor)
		if corruptLayer && i == 0 {
			layerDigest := strings.TrimPrefix(layerDescriptor.Digest, "sha256:")
			content := blobs[layerDigest]
			content[0] ^= 0xff
			blobs[layerDigest] = content
		}
	}
	indexBytes, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{"oci-layout": []byte(`{"imageLayoutVersion":"1.0.0"}`), "index.json": indexBytes}
	for digest, content := range blobs {
		files["blobs/sha256/"+digest] = content
	}
	path := filepath.Join(t.TempDir(), "k3s-airgap-images-amd64.tar")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := tar.NewWriter(file)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	// Keep archive ordering deterministic without depending on map order.
	sortStrings(names)
	for _, name := range names {
		data := files[name]
		header := &tar.Header{Name: name, Mode: 0644, Size: int64(len(data)), Typeflag: tar.TypeReg, ModTime: time.Unix(0, 0).UTC(), Format: tar.FormatUSTAR}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func fixtureBlob(t *testing.T, mediaType string, content []byte) fixtureDescriptor {
	t.Helper()
	digest := sha256.Sum256(content)
	return fixtureDescriptor{MediaType: mediaType, Digest: "sha256:" + hex.EncodeToString(digest[:]), Size: int64(len(content))}
}

func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

func createSystemImageApproval(t *testing.T, bundle, mirrorHost string, private ed25519.PrivateKey) ([]byte, []byte) {
	t.Helper()
	digest, _, err := inspectSystemImageBundle(bundle, mirrorHost)
	if err != nil {
		t.Fatal(err)
	}
	bundleURL := "https://mirror.customer.example/k3s/" + SystemImagesK3sVersion + "/linux-amd64/" + digest + "/" + SystemImagesBundleName
	lock, signature, err := CreateSystemImagesLock(bundle,
		bundleURL,
		mirrorHost,
		SystemImagesApprovalMetadata{
			BundleMirrorReference: bundleURL,
			ChecksumEvidenceRef:   "review-2026-0001", AcquisitionReference: "acquisition-2026-0001",
			ApprovalReference: "approval-2026-0001", ApprovedBy: "synthetic-fixture-only",
			ApprovedAt: "2026-11-21T12:00:00Z",
		}, private)
	if err != nil {
		t.Fatal(err)
	}
	return lock, signature
}

func TestVerifySystemImagesValidSignedBundleAndOfflineInventory(t *testing.T) {
	bundle := makeOCIImageBundle(t, "amd64", "", "", false)
	private, trust := imageFixtureKey(t)
	lock, signature := createSystemImageApproval(t, bundle, "registry.customer.internal", private)
	verified, err := VerifySystemImages(lock, signature, trust, bundle)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Lock.K3sVersion != SystemImagesK3sVersion || verified.Lock.Architecture != SystemImagesArch || len(verified.Lock.Images) != 8 {
		t.Fatalf("unexpected verified system image lock: %#v", verified.Lock)
	}
	inventory, err := verified.InventoryJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(inventory, []byte(`"mirrorReference": "registry.customer.internal/rancher/klipper-helm:v0.13.3-build20261021"`)) {
		t.Fatalf("inventory omitted the signed private reference: %s", inventory)
	}
}

func TestVerifySystemImagesRejectsUnsignedUntrustedAndModifiedLocks(t *testing.T) {
	bundle := makeOCIImageBundle(t, "amd64", "", "", false)
	private, trust := imageFixtureKey(t)
	lock, signature := createSystemImageApproval(t, bundle, "registry.customer.internal", private)
	if _, err := VerifySystemImages(lock, nil, trust, bundle); err == nil {
		t.Fatal("unsigned lock accepted")
	}
	badSignature := append([]byte(nil), signature...)
	badSignature[0] ^= 1
	if _, err := VerifySystemImages(lock, badSignature, trust, bundle); err == nil {
		t.Fatal("invalid signature accepted")
	}
	otherPrivate, otherTrust := imageFixtureKeyWithSeed(t, "untrusted image fixture key")
	_ = otherPrivate
	if _, err := VerifySystemImages(lock, signature, otherTrust, bundle); err == nil {
		t.Fatal("unknown key accepted")
	}
	modified := bytes.Replace(lock, []byte("approval_reference=approval-2026-0001"), []byte("approval_reference=approval-2026-9999"), 1)
	if _, err := VerifySystemImages(modified, signature, trust, bundle); err == nil {
		t.Fatal("modified approval metadata accepted")
	}
}

func imageFixtureKeyWithSeed(t *testing.T, label string) (ed25519.PrivateKey, []byte) {
	t.Helper()
	seed := sha256.Sum256([]byte(label))
	private := ed25519.NewKeyFromSeed(seed[:])
	public := private.Public().(ed25519.PublicKey)
	trust, err := EncodeTrust(map[string]ed25519.PublicKey{protocol.KeyID(public): public})
	if err != nil {
		t.Fatal(err)
	}
	return private, trust
}

func TestSystemImagesRejectsInvalidBundles(t *testing.T) {
	private, _ := imageFixtureKey(t)
	for name, bundle := range map[string]string{
		"missing image":        makeOCIImageBundle(t, "amd64", k3sSystemImageReferences[0], "", false),
		"unexpected image":     makeOCIImageBundle(t, "amd64", "", k3sSystemImageReferences[0], false),
		"wrong architecture":   makeOCIImageBundle(t, "arm64", "", "", false),
		"modified layer bytes": makeOCIImageBundle(t, "amd64", "", "", true),
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := CreateSystemImagesLock(bundle, "https://mirror.customer.example/bundle.tar", "registry.customer.internal", SystemImagesApprovalMetadata{
				BundleMirrorReference: "https://mirror.customer.example/bundle.tar", ChecksumEvidenceRef: "evidence-1", AcquisitionReference: "acquisition-1", ApprovalReference: "approval-1", ApprovedBy: "team", ApprovedAt: "2026-11-21T12:00:00Z",
			}, private)
			if err == nil {
				t.Fatal("invalid OCI bundle accepted")
			}
		})
	}
}

func TestVerifySystemImagesRejectsBundleTamperingAndWrongVersion(t *testing.T) {
	bundle := makeOCIImageBundle(t, "amd64", "", "", false)
	private, trust := imageFixtureKey(t)
	lock, signature := createSystemImageApproval(t, bundle, "registry.customer.internal", private)
	bytesOnDisk, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	bytesOnDisk[len(bytesOnDisk)-1024] ^= 0x01
	if err := os.WriteFile(bundle, bytesOnDisk, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySystemImages(lock, signature, trust, bundle); err == nil {
		t.Fatal("modified bundle bytes accepted")
	}

	wrongBundle := makeOCIImageBundle(t, "amd64", "", "", false)
	lock, _ = createSystemImageApproval(t, wrongBundle, "registry.customer.internal", private)
	wrong := bytes.Replace(lock, []byte("k3s_version="+SystemImagesK3sVersion), []byte("k3s_version=v1.0.0+k3s0"), 1)
	parsed, err := parseSystemImagesLock(wrong)
	if err != nil {
		t.Fatal(err)
	}
	// A customer key can sign malformed policy content, but supported-version
	// validation still rejects it after authenticating the exact bytes.
	badSignature := []byte(base64SignatureForTest(ed25519.Sign(private, append([]byte(SystemImagesDomain), parsed.Canonical()...))))
	if _, err := VerifySystemImages(wrong, badSignature, trust, wrongBundle); err == nil {
		t.Fatal("wrong K3s version accepted")
	}

	lock, signature = createSystemImageApproval(t, wrongBundle, "registry.customer.internal", private)
	parsed, err = parseSystemImagesLock(lock)
	if err != nil {
		t.Fatal(err)
	}
	parsed.Images[0].Digest = "sha256:" + strings.Repeat("0", 64)
	wrongDigestLock := parsed.Canonical()
	wrongDigestSignature := []byte(base64SignatureForTest(ed25519.Sign(private, append([]byte(SystemImagesDomain), wrongDigestLock...))))
	if _, err := VerifySystemImages(wrongDigestLock, wrongDigestSignature, trust, wrongBundle); err == nil {
		t.Fatal("signed image digest that mismatches the archive was accepted")
	}
}

func TestSystemImageLockRejectsMissingMirrorAndMalformedCanonicalFields(t *testing.T) {
	bundle := makeOCIImageBundle(t, "amd64", "", "", false)
	private, trust := imageFixtureKey(t)
	digest, _, err := inspectSystemImageBundle(bundle, "registry.customer.internal")
	if err != nil {
		t.Fatal(err)
	}
	bundleURL := "https://mirror.customer.example/k3s/" + SystemImagesK3sVersion + "/linux-amd64/" + digest + "/" + SystemImagesBundleName
	metadata := SystemImagesApprovalMetadata{BundleMirrorReference: bundleURL, ChecksumEvidenceRef: "evidence-1", AcquisitionReference: "acquisition-1", ApprovalReference: "approval-1", ApprovedBy: "team", ApprovedAt: "2026-11-21T12:00:00Z"}
	if _, _, err := CreateSystemImagesLock(bundle, metadata.BundleMirrorReference, "", metadata, private); err == nil {
		t.Fatal("missing private registry mapping accepted")
	}
	if _, _, err := CreateSystemImagesLock(bundle, metadata.BundleMirrorReference, "docker.io", metadata, private); err == nil {
		t.Fatal("public source registry accepted as the private mirror")
	}
	wrongLocation := strings.Replace(metadata.BundleMirrorReference, "/k3s/", "/other/", 1)
	if _, _, err := CreateSystemImagesLock(bundle, wrongLocation, "registry.customer.internal", SystemImagesApprovalMetadata{
		BundleMirrorReference: wrongLocation, ChecksumEvidenceRef: "evidence-1", AcquisitionReference: "acquisition-1",
		ApprovalReference: "approval-1", ApprovedBy: "team", ApprovedAt: "2026-11-21T12:00:00Z",
	}, private); err == nil {
		t.Fatal("non-content-addressed mirror path accepted")
	}
	lock, signature := createSystemImageApproval(t, bundle, "registry.customer.internal", private)
	for name, candidate := range map[string][]byte{
		"duplicate field":    bytes.Replace(lock, []byte("manifest_version=1\n"), []byte("manifest_version=1\nmanifest_version=1\n"), 1),
		"unsupported schema": bytes.Replace(lock, []byte(SystemImagesLockHeader), []byte("KORDEX-CUSTOMER-K3S-SYSTEM-IMAGES-LOCK-V9"), 1),
		"missing image row":  bytes.Replace(lock, []byte("image_count=8\n"), []byte("image_count=7\n"), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifySystemImages(candidate, signature, trust, bundle); err == nil {
				t.Fatal("malformed system image lock accepted")
			}
		})
	}
}

func TestStageSystemImagesIsAtomicAndIdempotent(t *testing.T) {
	bundle := makeOCIImageBundle(t, "amd64", "", "", false)
	private, trust := imageFixtureKey(t)
	lock, signature := createSystemImageApproval(t, bundle, "registry.customer.internal", private)
	root := t.TempDir()
	first, _, err := StageSystemImages(lock, signature, trust, bundle, root)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := StageSystemImages(lock, signature, trust, bundle, root)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("staging path changed across retries: %q vs %q", first, second)
	}
	expectedDigest, _, err := inspectSystemImageBundle(bundle, "registry.customer.internal")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(first) != expectedDigest || !strings.Contains(first, "/k3s/"+SystemImagesK3sVersion+"/linux-amd64/") {
		t.Fatalf("staging path is not content-addressed by release, architecture, and archive digest: %q", first)
	}
	for _, name := range []string{SystemImagesBundleName, "k3s-system-images.lock", "k3s-system-images.lock.sig", "inventory.json", "registries.yaml"} {
		if _, err := os.Stat(filepath.Join(first, name)); err != nil {
			t.Fatalf("staged artifact %s is missing: %v", name, err)
		}
	}
	registryConfig, err := os.ReadFile(filepath.Join(first, "registries.yaml"))
	if err != nil || !bytes.Equal(registryConfig, []byte("mirrors:\n  docker.io:\n    endpoint:\n      - \"https://registry.customer.internal\"\n")) {
		t.Fatalf("staged registry configuration is not derived from the signed mirror: %s (%v)", registryConfig, err)
	}
	if err := os.WriteFile(filepath.Join(first, "registries.yaml"), []byte("mirrors: {}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := StageSystemImages(lock, signature, trust, bundle, root); err == nil {
		t.Fatal("conflicting staged registry configuration was overwritten")
	}
	if err := os.WriteFile(filepath.Join(first, "registries.yaml"), registryConfig, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(first, SystemImagesBundleName), []byte("corrupt"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := StageSystemImages(lock, signature, trust, bundle, root); err == nil {
		t.Fatal("conflicting staged output was overwritten")
	}
}

func TestStageSystemImagesRejectsDanglingDestinationSymlink(t *testing.T) {
	bundle := makeOCIImageBundle(t, "amd64", "", "", false)
	private, trust := imageFixtureKey(t)
	lock, signature := createSystemImageApproval(t, bundle, "registry.customer.internal", private)
	digest, _, err := inspectSystemImageBundle(bundle, "registry.customer.internal")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	parent := filepath.Join(root, "k3s", SystemImagesK3sVersion, "linux-amd64")
	if err := os.MkdirAll(parent, 0755); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(parent, digest)
	if err := os.Symlink(filepath.Join(root, "missing-target"), destination); err != nil {
		t.Fatal(err)
	}
	if _, _, err := StageSystemImages(lock, signature, trust, bundle, root); err == nil {
		t.Fatal("dangling symlink at the content-addressed destination was treated as absent")
	}
	info, err := os.Lstat(destination)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("conflicting dangling symlink was replaced: info=%v err=%v", info, err)
	}
}

func base64SignatureForTest(signature []byte) string {
	return base64.RawStdEncoding.EncodeToString(signature) + "\n"
}
