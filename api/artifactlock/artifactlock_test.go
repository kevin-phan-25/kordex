package artifactlock

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kordex.local/api/protocol"
)

func fixture(t *testing.T) (string, ed25519.PrivateKey, []byte) {
	t.Helper()
	seed := sha256.Sum256([]byte("synthetic test key; not production trust"))
	private := ed25519.NewKeyFromSeed(seed[:])
	trust, err := EncodeTrust(map[string]ed25519.PublicKey{keyID(private): private.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	current, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "synthetic-k3s-fixture")
	data, err := os.ReadFile(current)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binary, data, 0700); err != nil {
		t.Fatal(err)
	}
	return binary, private, trust
}

func keyID(private ed25519.PrivateKey) string {
	return protocol.KeyID(private.Public().(ed25519.PublicKey))
}

func makeSigned(t *testing.T, binary string, private ed25519.PrivateKey) ([]byte, []byte) {
	t.Helper()
	lock, sig, err := CreateK3sLock(binary, ApprovalMetadata{
		MirrorReference:      "https://mirror.customer.example/k3s/v1.36.6%2Bk3s1/linux-amd64/k3s",
		ChecksumEvidenceRef:  "supply-chain-review-2026-0042",
		AcquisitionReference: "acquisition-2026-0042",
		ApprovalReference:    "change-approval-2026-0042",
		ApprovedBy:           "platform-supply-chain-team",
		ApprovedAt:           "2026-11-20T12:00:00Z",
	}, private)
	if err != nil {
		t.Fatal(err)
	}
	return lock, sig
}

func testVersion(string) (string, error) {
	return "k3s version " + ArtifactVersion + " (synthetic-fixture)\n", nil
}

func TestVerifyValidSignedLockAndMatchingBinary(t *testing.T) {
	binary, private, trust := fixture(t)
	lock, sig := makeSigned(t, binary, private)
	verified, err := Verify(lock, sig, trust, binary, testVersion)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Lock.Version != ArtifactVersion || verified.Lock.Architecture != Architecture || verified.Digest != verified.Lock.Digest {
		t.Fatalf("unexpected verified result: %#v", verified)
	}
}

func TestVerifyRejectsBinaryDigestMismatch(t *testing.T) {
	binary, private, trust := fixture(t)
	lock, sig := makeSigned(t, binary, private)
	if err := os.WriteFile(binary, []byte("tampered synthetic artifact"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(lock, sig, trust, binary, testVersion); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("expected digest rejection, got %v", err)
	}
}

func TestVerifyRejectsInvalidSignatureAndUnknownSigner(t *testing.T) {
	binary, private, trust := fixture(t)
	lock, sig := makeSigned(t, binary, private)
	badSig := append([]byte(nil), sig...)
	badSig[0] ^= 1
	if _, err := Verify(lock, badSig, trust, binary, testVersion); err == nil {
		t.Fatal("invalid signature accepted")
	}
	if _, err := Verify(lock, []byte("not-base64!\n"), trust, binary, testVersion); err == nil {
		t.Fatal("malformed signature encoding accepted")
	}
	otherSeed := sha256.Sum256([]byte("another synthetic untrusted test key"))
	other := ed25519.NewKeyFromSeed(otherSeed[:])
	otherTrust, err := EncodeTrust(map[string]ed25519.PublicKey{keyID(other): other.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(lock, sig, otherTrust, binary, testVersion); err == nil || !strings.Contains(err.Error(), "not in") {
		t.Fatalf("expected unknown signer rejection, got %v", err)
	}
}

func TestVerifyRejectsModifiedSignedFieldsBeforeUsingDigest(t *testing.T) {
	binary, private, trust := fixture(t)
	lock, sig := makeSigned(t, binary, private)
	cases := map[string][2]string{
		"version":            {"version=" + ArtifactVersion, "version=v9.9.9+k3s9"},
		"architecture":       {"architecture=" + Architecture, "architecture=linux/arm64"},
		"source":             {"source_url=" + SourceURL, "source_url=https://untrusted.example/k3s"},
		"digest":             {"digest=" + strings.Split(string(lock), "digest=")[1][:64], "digest=" + strings.Repeat("0", 64)},
		"mirror":             {"mirror_reference=https://mirror.customer.example/k3s/v1.36.6%2Bk3s1/linux-amd64/k3s", "mirror_reference=https://other.example/k3s"},
		"acquisition":        {"acquisition_reference=acquisition-2026-0042", "acquisition_reference=other-acquisition"},
		"evidence":           {"checksum_evidence_ref=supply-chain-review-2026-0042", "checksum_evidence_ref=other-evidence"},
		"approval reference": {"approval_reference=change-approval-2026-0042", "approval_reference=other-approval"},
		"approver":           {"approved_by=platform-supply-chain-team", "approved_by=other-team"},
		"approval time":      {"approved_at=2026-11-20T12:00:00Z", "approved_at=2026-11-21T12:00:00Z"},
	}
	for name, replacement := range cases {
		t.Run(name, func(t *testing.T) {
			changed := []byte(strings.Replace(string(lock), replacement[0], replacement[1], 1))
			if _, err := Verify(changed, sig, trust, binary, testVersion); err == nil || !strings.Contains(err.Error(), "signature") {
				t.Fatalf("modified %s accepted or parsed past signature: %v", name, err)
			}
		})
	}
}

func TestVerifyRejectsMalformedUnsupportedAndInvalidLocks(t *testing.T) {
	binary, private, trust := fixture(t)
	lock, sig := makeSigned(t, binary, private)
	cases := map[string][]byte{
		"duplicate field":    []byte(strings.Replace(string(lock), "artifact=k3s\n", "artifact=k3s\nartifact=k3s\n", 1)),
		"missing newline":    bytesTrimFinalNewline(lock),
		"unsupported schema": []byte(strings.Replace(string(lock), LockHeader, "KORDEX-CUSTOMER-ARTIFACT-LOCK-V9", 1)),
	}
	for name, candidate := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Verify(candidate, sig, trust, binary, testVersion); err == nil {
				t.Fatal("malformed lock accepted")
			}
		})
	}
	unsigned := Lock{Artifact: ArtifactName, Version: ArtifactVersion, Architecture: Architecture, DigestAlgorithm: "sha512", Digest: strings.Repeat("a", 64), SourceURL: SourceURL, MirrorReference: "https://mirror.customer.example/k3s", ChecksumEvidenceRef: "evidence-1", AcquisitionReference: "acquisition-1", ApprovalReference: "approval-1", ApprovedBy: "team", ApprovedAt: "2026-11-20T12:00:00Z", SignerKeyID: keyID(private)}
	unsignedBytes := unsigned.Canonical()
	unsignedSig := []byte(base64Signature(ed25519.Sign(private, signingMessage(unsignedBytes))))
	if _, err := Verify(unsignedBytes, unsignedSig, trust, binary, testVersion); err == nil || !strings.Contains(err.Error(), "algorithm") {
		t.Fatalf("unsupported digest algorithm accepted: %v", err)
	}
	badVersion := unsigned
	badVersion.DigestAlgorithm = DigestAlgorithm
	badVersion.Version = "v0.0.0+k3s0"
	versionBytes := badVersion.Canonical()
	versionSig := []byte(base64Signature(ed25519.Sign(private, signingMessage(versionBytes))))
	if _, err := Verify(versionBytes, versionSig, trust, binary, testVersion); err == nil {
		t.Fatal("unsupported artifact version accepted")
	}
}

func TestVerifyRequiresTrustAndRejectsUnsafeBinaryPath(t *testing.T) {
	binary, private, trust := fixture(t)
	lock, sig := makeSigned(t, binary, private)
	if _, err := Verify(lock, sig, nil, binary, testVersion); err == nil {
		t.Fatal("missing trust bundle accepted")
	}
	symlink := filepath.Join(t.TempDir(), "k3s-link")
	if err := os.Symlink(binary, symlink); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if _, err := Verify(lock, sig, trust, symlink, testVersion); err == nil {
		t.Fatal("symlink binary accepted")
	}
}

func TestVerifyRotationTrustAndVersionMismatch(t *testing.T) {
	binary, oldPrivate, _ := fixture(t)
	lock, sig := makeSigned(t, binary, oldPrivate)
	newSeed := sha256.Sum256([]byte("synthetic rotated customer artifact key"))
	newPrivate := ed25519.NewKeyFromSeed(newSeed[:])
	trust, err := EncodeTrust(map[string]ed25519.PublicKey{
		keyID(oldPrivate): oldPrivate.Public().(ed25519.PublicKey),
		keyID(newPrivate): newPrivate.Public().(ed25519.PublicKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(lock, sig, trust, binary, testVersion); err != nil {
		t.Fatalf("overlap trust rejected old approved lock: %v", err)
	}
	wrongVersion := func(string) (string, error) { return "k3s version v9.9.9+k3s9\n", nil }
	if _, err := Verify(lock, sig, trust, binary, wrongVersion); err == nil || !strings.Contains(err.Error(), "different") {
		t.Fatalf("binary version mismatch accepted: %v", err)
	}
}

func TestVerifyRejectsNonAMD64ELF(t *testing.T) {
	binary, private, trust := fixture(t)
	data, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	// ELF e_machine is bytes 18-19 in the little-endian ELF header. AArch64 is 183.
	if len(data) < 20 || string(data[:4]) != "\x7fELF" {
		t.Fatal("test binary is not ELF")
	}
	data[18], data[19] = 183, 0
	if err := os.WriteFile(binary, data, 0700); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(data)
	lock, sig, err := Sign(Lock{
		Artifact: ArtifactName, Version: ArtifactVersion, Architecture: Architecture,
		DigestAlgorithm: DigestAlgorithm, Digest: hex.EncodeToString(h[:]), SourceURL: SourceURL,
		MirrorReference:     "https://mirror.customer.example/k3s/v1.36.6%2Bk3s1/linux-amd64/k3s",
		ChecksumEvidenceRef: "evidence-1", AcquisitionReference: "acquisition-1",
		ApprovalReference: "approval-1", ApprovedBy: "platform-team", ApprovedAt: "2026-11-20T12:00:00Z",
	}, private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(lock, sig, trust, binary, testVersion); err == nil || !strings.Contains(err.Error(), "linux/amd64") {
		t.Fatalf("non-amd64 artifact accepted: %v", err)
	}
}

func TestTrustBundleRejectsDuplicatesAndEncodingAmbiguity(t *testing.T) {
	_, private, trust := fixture(t)
	line := strings.Split(string(trust), "\n")[1]
	if _, err := ParseTrust([]byte(TrustHeader + "\n" + line + "\n" + line + "\n")); err == nil {
		t.Fatal("duplicate trust key accepted")
	}
	if _, err := ParseTrust([]byte(strings.Replace(string(trust), " ", "  ", 1))); err == nil {
		t.Fatal("ambiguous trust encoding accepted")
	}
	if _, err := EncodeTrust(map[string]ed25519.PublicKey{"wrong": private.Public().(ed25519.PublicKey)}); err == nil {
		t.Fatal("mismatched key ID accepted")
	}
}

func TestSignRejectsMirrorTraversal(t *testing.T) {
	binary, private, _ := fixture(t)
	_, _, err := CreateK3sLock(binary, ApprovalMetadata{MirrorReference: "https://mirror.example/../outside", ChecksumEvidenceRef: "evidence-1", AcquisitionReference: "acquisition-1", ApprovalReference: "approval-1", ApprovedBy: "team", ApprovedAt: "2026-11-20T12:00:00Z"}, private)
	if err == nil {
		t.Fatal("mirror path traversal accepted")
	}
}

func bytesTrimFinalNewline(input []byte) []byte { return input[:len(input)-1] }

func base64Signature(signature []byte) string {
	return base64.RawStdEncoding.EncodeToString(signature) + "\n"
}
