// Package artifactlock verifies customer-approved offline artifacts. Its
// trust bundle and signature domain are deliberately separate from Kordex
// maintenance, release, and tool-provenance trust.
package artifactlock

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"debug/elf"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"kordex.local/api/protocol"
)

const (
	TrustHeader     = "KORDEX-CUSTOMER-ARTIFACT-TRUST-V1"
	LockHeader      = "KORDEX-CUSTOMER-ARTIFACT-LOCK-V1"
	SignatureDomain = "kordex.customer-artifact-approval.v1\n"
	ArtifactName    = "k3s"
	ArtifactVersion = "v1.36.6+k3s1"
	Architecture    = "linux/amd64"
	DigestAlgorithm = "sha256"
	SourceURL       = "https://github.com/k3s-io/k3s/releases/download/v1.36.6%2Bk3s1/k3s"
	maxLockBytes    = 16 << 10
	maxTrustBytes   = 16 << 10
	maxBinarySize   = 512 << 20
	maxTrustKeys    = 16
)

var referencePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+%-]{0,511}$`)
var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var keyIDPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// Lock uses a fixed-order line format. The exact bytes are signed, avoiding
// JSON duplicate-key and canonicalization ambiguity.
type Lock struct {
	Artifact             string
	Version              string
	Architecture         string
	DigestAlgorithm      string
	Digest               string
	SourceURL            string
	MirrorReference      string
	ChecksumEvidenceRef  string
	AcquisitionReference string
	ApprovalReference    string
	ApprovedBy           string
	ApprovedAt           string
	SignerKeyID          string
}

type Verified struct {
	Lock   Lock
	Digest string
}

// ApprovalMetadata is customer-supplied evidence. The verifier does not infer
// or authenticate the referenced approval system; its values are signed.
type ApprovalMetadata struct {
	MirrorReference      string
	ChecksumEvidenceRef  string
	AcquisitionReference string
	ApprovalReference    string
	ApprovedBy           string
	ApprovedAt           string
}

// CreateK3sLock hashes and architecture-checks a local, already acquired K3s
// binary, then signs the customer-provided approval metadata. It does not fetch
// the source URL, execute the binary, create keys, or assert upstream provenance.
func CreateK3sLock(binaryPath string, metadata ApprovalMetadata, private ed25519.PrivateKey) ([]byte, []byte, error) {
	digest, err := inspectBinary(binaryPath)
	if err != nil {
		return nil, nil, err
	}
	return Sign(Lock{
		Artifact: ArtifactName, Version: ArtifactVersion, Architecture: Architecture,
		DigestAlgorithm: DigestAlgorithm, Digest: digest, SourceURL: SourceURL,
		MirrorReference: metadata.MirrorReference, ChecksumEvidenceRef: metadata.ChecksumEvidenceRef,
		AcquisitionReference: metadata.AcquisitionReference, ApprovalReference: metadata.ApprovalReference,
		ApprovedBy: metadata.ApprovedBy, ApprovedAt: metadata.ApprovedAt,
	}, private)
}

// ParseTrust parses a separately provisioned, sorted public-key bundle.
// Every key identifier is checked against the decoded Ed25519 public key.
func ParseTrust(data []byte) (map[string]ed25519.PublicKey, error) {
	if len(data) == 0 || len(data) > maxTrustBytes || !bytes.HasSuffix(data, []byte("\n")) {
		return nil, errors.New("invalid customer artifact trust bundle size or termination")
	}
	lines := strings.Split(string(data[:len(data)-1]), "\n")
	if len(lines) < 2 || lines[0] != TrustHeader || len(lines)-1 > maxTrustKeys {
		return nil, errors.New("invalid customer artifact trust bundle header or key count")
	}
	keys := make(map[string]ed25519.PublicKey, len(lines)-1)
	previous := ""
	for _, line := range lines[1:] {
		parts := strings.Split(line, " ")
		if len(parts) != 2 || !keyIDPattern.MatchString(parts[0]) || parts[0] <= previous {
			return nil, errors.New("customer artifact trust keys must be unique and sorted")
		}
		key, err := protocol.DecodeKey(parts[1])
		if err != nil || protocol.KeyID(key) != parts[0] || protocol.EncodeKey(key) != parts[1] {
			return nil, errors.New("invalid customer artifact public key entry")
		}
		keys[parts[0]] = key
		previous = parts[0]
	}
	return keys, nil
}

// EncodeTrust serializes already-authorized public keys. It does not create
// keys or establish trust; callers must distribute the result independently.
func EncodeTrust(keys map[string]ed25519.PublicKey) ([]byte, error) {
	if len(keys) == 0 || len(keys) > maxTrustKeys {
		return nil, errors.New("customer artifact trust requires 1 to 16 approved keys")
	}
	ids := make([]string, 0, len(keys))
	for id, key := range keys {
		if !keyIDPattern.MatchString(id) || len(key) != ed25519.PublicKeySize || protocol.KeyID(key) != id {
			return nil, errors.New("customer artifact trust key ID does not match public key")
		}
		ids = append(ids, id)
	}
	// Sorting is small and keeps the format stable across implementations.
	for i := 1; i < len(ids); i++ {
		for j := i; j > 0 && ids[j] < ids[j-1]; j-- {
			ids[j], ids[j-1] = ids[j-1], ids[j]
		}
	}
	var b strings.Builder
	b.WriteString(TrustHeader + "\n")
	for _, id := range ids {
		b.WriteString(id + " " + protocol.EncodeKey(keys[id]) + "\n")
	}
	return []byte(b.String()), nil
}

// Canonical returns the signed lock bytes in the one supported field order.
func (l Lock) Canonical() []byte {
	values := []string{
		LockHeader,
		"artifact=" + l.Artifact,
		"version=" + l.Version,
		"architecture=" + l.Architecture,
		"digest_algorithm=" + l.DigestAlgorithm,
		"digest=" + l.Digest,
		"source_url=" + l.SourceURL,
		"mirror_reference=" + l.MirrorReference,
		"checksum_evidence_ref=" + l.ChecksumEvidenceRef,
		"acquisition_reference=" + l.AcquisitionReference,
		"approval_reference=" + l.ApprovalReference,
		"approved_by=" + l.ApprovedBy,
		"approved_at=" + l.ApprovedAt,
		"signer_key_id=" + l.SignerKeyID,
	}
	return []byte(strings.Join(values, "\n") + "\n")
}

func parseLock(data []byte) (Lock, error) {
	if len(data) == 0 || len(data) > maxLockBytes || !bytes.HasSuffix(data, []byte("\n")) {
		return Lock{}, errors.New("invalid customer artifact lock size or termination")
	}
	lines := strings.Split(string(data[:len(data)-1]), "\n")
	keys := []string{"artifact", "version", "architecture", "digest_algorithm", "digest", "source_url", "mirror_reference", "checksum_evidence_ref", "acquisition_reference", "approval_reference", "approved_by", "approved_at", "signer_key_id"}
	if len(lines) != len(keys)+1 || lines[0] != LockHeader {
		return Lock{}, errors.New("unsupported customer artifact lock format")
	}
	values := make([]string, len(keys))
	for i, name := range keys {
		prefix := name + "="
		if !strings.HasPrefix(lines[i+1], prefix) {
			return Lock{}, fmt.Errorf("customer artifact lock field %q is missing, duplicated, or out of order", name)
		}
		values[i] = strings.TrimPrefix(lines[i+1], prefix)
		if values[i] == "" || strings.ContainsAny(values[i], "\r\x00") {
			return Lock{}, fmt.Errorf("customer artifact lock field %q is empty or malformed", name)
		}
	}
	return Lock{Artifact: values[0], Version: values[1], Architecture: values[2], DigestAlgorithm: values[3], Digest: values[4], SourceURL: values[5], MirrorReference: values[6], ChecksumEvidenceRef: values[7], AcquisitionReference: values[8], ApprovalReference: values[9], ApprovedBy: values[10], ApprovedAt: values[11], SignerKeyID: values[12]}, nil
}

func validateLock(l Lock) error {
	if l.Artifact != ArtifactName || l.Version != ArtifactVersion || l.Architecture != Architecture || l.DigestAlgorithm != DigestAlgorithm || l.SourceURL != SourceURL {
		return errors.New("artifact lock does not match the approved K3s name, version, architecture, algorithm, and upstream source")
	}
	if !digestPattern.MatchString(l.Digest) || !keyIDPattern.MatchString(l.SignerKeyID) {
		return errors.New("artifact lock contains an invalid digest or signer key ID")
	}
	for field, value := range map[string]string{"mirror reference": l.MirrorReference, "checksum evidence reference": l.ChecksumEvidenceRef, "acquisition reference": l.AcquisitionReference, "approval reference": l.ApprovalReference, "approver": l.ApprovedBy} {
		if !referencePattern.MatchString(value) || strings.Contains(value, "..") || strings.HasPrefix(value, "/") {
			return fmt.Errorf("artifact lock has an invalid %s", field)
		}
	}
	mirror, err := url.Parse(l.MirrorReference)
	decodedPath, decodeErr := url.PathUnescape(mirrorPath(mirror))
	if err != nil || decodeErr != nil || strings.Contains(decodedPath, "%") || mirror.Scheme != "https" || mirror.Host == "" || mirror.User != nil || mirror.RawQuery != "" || mirror.Fragment != "" || pathHasTraversal(decodedPath) {
		return errors.New("artifact lock mirror reference must be a traversal-free HTTPS URL without credentials, query, or fragment")
	}
	if _, err := time.Parse(time.RFC3339Nano, l.ApprovedAt); err != nil || !strings.HasSuffix(l.ApprovedAt, "Z") {
		return errors.New("artifact lock approval time must be canonical UTC RFC3339")
	}
	t, _ := time.Parse(time.RFC3339Nano, l.ApprovedAt)
	if t.UTC().Format(time.RFC3339Nano) != l.ApprovedAt {
		return errors.New("artifact lock approval time is not canonical")
	}
	return nil
}

func mirrorPath(u *url.URL) string {
	if u == nil {
		return ""
	}
	return u.EscapedPath()
}

func pathHasTraversal(path string) bool {
	for _, segment := range strings.Split(path, "/") {
		if segment == "." || segment == ".." {
			return true
		}
	}
	return false
}

func signingMessage(lock []byte) []byte { return append([]byte(SignatureDomain), lock...) }

// Sign signs a validated lock using an already provisioned customer key.
// This function never generates or exports keys.
func Sign(l Lock, private ed25519.PrivateKey) ([]byte, []byte, error) {
	if len(private) != ed25519.PrivateKeySize {
		return nil, nil, errors.New("invalid customer artifact signing key")
	}
	if !private.Equal(ed25519.NewKeyFromSeed(private.Seed())) {
		return nil, nil, errors.New("invalid customer artifact signing key encoding")
	}
	l.SignerKeyID = protocol.KeyID(private.Public().(ed25519.PublicKey))
	if err := validateLock(l); err != nil {
		return nil, nil, err
	}
	lock := l.Canonical()
	sig := base64.RawStdEncoding.EncodeToString(ed25519.Sign(private, signingMessage(lock))) + "\n"
	return lock, []byte(sig), nil
}

// Verify authenticates the exact lock bytes before validating or using its
// digest, then hashes and inspects the local binary. It performs no network
// access. The version runner is injectable for tests; production runs the
// already signature- and digest-verified local binary with --version.
func Verify(lockBytes, signatureBytes, trustBytes []byte, binaryPath string, versionRunner func(string) (string, error)) (Verified, error) {
	l, err := parseLock(lockBytes)
	if err != nil {
		return Verified{}, err
	}
	if !keyIDPattern.MatchString(l.SignerKeyID) {
		return Verified{}, errors.New("invalid signer key ID in customer artifact lock")
	}
	keys, err := ParseTrust(trustBytes)
	if err != nil {
		return Verified{}, err
	}
	public, ok := keys[l.SignerKeyID]
	if !ok {
		return Verified{}, errors.New("customer artifact lock signer is not in the independently provisioned trust bundle")
	}
	sigText := string(signatureBytes)
	if len(signatureBytes) > 128 || !strings.HasSuffix(sigText, "\n") || strings.ContainsAny(strings.TrimSuffix(sigText, "\n"), "\r\n") {
		return Verified{}, errors.New("malformed customer artifact lock signature")
	}
	sig, err := base64.RawStdEncoding.DecodeString(strings.TrimSuffix(sigText, "\n"))
	if err != nil || len(sig) != ed25519.SignatureSize || base64.RawStdEncoding.EncodeToString(sig) != strings.TrimSuffix(sigText, "\n") {
		return Verified{}, errors.New("malformed customer artifact lock signature")
	}
	if !ed25519.Verify(public, signingMessage(lockBytes), sig) {
		return Verified{}, errors.New("customer artifact lock signature verification failed")
	}
	if err := validateLock(l); err != nil {
		return Verified{}, err
	}
	verifiedPath, cleanup, actual, err := snapshotBinary(binaryPath, l.Digest)
	if err != nil {
		return Verified{}, err
	}
	defer cleanup()
	if versionRunner == nil {
		versionRunner = runVersion
	}
	output, err := versionRunner(verifiedPath)
	if err != nil {
		return Verified{}, fmt.Errorf("authenticated K3s binary version check failed: %w", err)
	}
	if !versionOutputMatches(output, ArtifactVersion) {
		return Verified{}, errors.New("authenticated K3s binary reports a version different from the approved lock")
	}
	after, err := digestRegularFile(verifiedPath)
	if err != nil || after != actual {
		return Verified{}, errors.New("verified K3s binary changed during its version check")
	}
	return Verified{Lock: l, Digest: actual}, nil
}

func inspectBinary(path string) (string, error) {
	f, info, err := openRegularNoSymlink(path, maxBinarySize)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", errors.New("could not hash K3s binary")
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", errors.New("could not inspect K3s binary")
	}
	e, err := elf.NewFile(f)
	if err != nil || e.Class != elf.ELFCLASS64 || e.Machine != elf.EM_X86_64 || e.Data != elf.ELFDATA2LSB || (e.OSABI != elf.ELFOSABI_NONE && e.OSABI != elf.ELFOSABI_LINUX) {
		return "", errors.New("K3s artifact is not a 64-bit little-endian linux/amd64 ELF binary")
	}
	if err := e.Close(); err != nil {
		return "", errors.New("could not close K3s ELF reader")
	}
	after, err := f.Stat()
	if err != nil || !os.SameFile(info, after) || info.Size() != after.Size() || !info.ModTime().Equal(after.ModTime()) {
		return "", errors.New("K3s binary changed while being inspected")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func snapshotBinary(path, expectedDigest string) (string, func(), string, error) {
	f, info, err := openRegularNoSymlink(path, maxBinarySize)
	if err != nil {
		return "", func() {}, "", err
	}
	dir, err := os.MkdirTemp("", "kordex-artifact-verify-")
	if err != nil {
		_ = f.Close()
		return "", func() {}, "", errors.New("could not create private artifact verification directory")
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	if err := os.Chmod(dir, 0700); err != nil {
		_ = f.Close()
		cleanup()
		return "", func() {}, "", errors.New("could not secure artifact verification directory")
	}
	target := filepath.Join(dir, "k3s")
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		_ = f.Close()
		cleanup()
		return "", func() {}, "", errors.New("could not stage K3s binary for verification")
	}
	h := sha256.New()
	_, copyErr := io.Copy(out, io.TeeReader(f, h))
	if copyErr == nil {
		copyErr = out.Sync()
	}
	if closeErr := out.Close(); copyErr == nil {
		copyErr = closeErr
	}
	after, statErr := f.Stat()
	_ = f.Close()
	if copyErr != nil || statErr != nil || !os.SameFile(info, after) || info.Size() != after.Size() || !info.ModTime().Equal(after.ModTime()) {
		cleanup()
		return "", func() {}, "", errors.New("K3s binary changed while being copied for verification")
	}
	digest := hex.EncodeToString(h.Sum(nil))
	if digest != expectedDigest {
		cleanup()
		return "", func() {}, "", errors.New("K3s binary SHA-256 does not match the authenticated artifact lock")
	}
	if err := os.Chmod(target, 0500); err != nil {
		cleanup()
		return "", func() {}, "", errors.New("could not secure staged K3s binary")
	}
	if err := verifyELFAMD64(target); err != nil {
		cleanup()
		return "", func() {}, "", err
	}
	return target, cleanup, digest, nil
}

func digestRegularFile(path string) (string, error) {
	f, info, err := openRegularNoSymlink(path, maxBinarySize)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", errors.New("could not hash K3s binary")
	}
	infoAfter, err := f.Stat()
	if err != nil || !os.SameFile(info, infoAfter) || infoAfter.Size() != info.Size() || !infoAfter.ModTime().Equal(info.ModTime()) {
		return "", errors.New("K3s binary changed while being verified")
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", errors.New("could not rewind K3s binary")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func verifyELFAMD64(path string) error {
	f, _, err := openRegularNoSymlink(path, maxBinarySize)
	if err != nil {
		return err
	}
	defer f.Close()
	e, err := elf.NewFile(f)
	if err != nil || e.Class != elf.ELFCLASS64 || e.Machine != elf.EM_X86_64 || e.Data != elf.ELFDATA2LSB || (e.OSABI != elf.ELFOSABI_NONE && e.OSABI != elf.ELFOSABI_LINUX) {
		return errors.New("K3s artifact is not a 64-bit little-endian linux/amd64 ELF binary")
	}
	return nil
}

func openRegularNoSymlink(path string, max int64) (*os.File, os.FileInfo, error) {
	if path == "" {
		return nil, nil, errors.New("artifact path is required")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, errors.New("artifact input is unavailable")
	}
	info, err := f.Stat()
	linkInfo, linkErr := os.Lstat(path)
	if err != nil || linkErr != nil || !info.Mode().IsRegular() || linkInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, linkInfo) || info.Size() <= 0 || info.Size() > max {
		_ = f.Close()
		return nil, nil, errors.New("artifact input must be a bounded regular non-symlink file")
	}
	return f, info, nil
}

func runVersion(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", errors.New("could not resolve verified binary path")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, abs, "--version")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	var out boundedOutput
	cmd.Stdout, cmd.Stderr = &out, &out
	err = cmd.Run()
	if ctx.Err() != nil {
		return "", errors.New("version command timed out")
	}
	if err != nil {
		return "", errors.New("version command failed")
	}
	return out.String(), nil
}

type boundedOutput struct{ b bytes.Buffer }

func (o *boundedOutput) Write(p []byte) (int, error) {
	remaining := 4096 - o.b.Len()
	if remaining > 0 {
		if len(p) > remaining {
			_, _ = o.b.Write(p[:remaining])
		} else {
			_, _ = o.b.Write(p)
		}
	}
	return len(p), nil
}
func (o *boundedOutput) String() string { return o.b.String() }

func versionOutputMatches(output, expected string) bool {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "k3s version ") {
			rest := strings.TrimPrefix(line, "k3s version ")
			version, _, _ := strings.Cut(rest, " ")
			return version == expected
		}
	}
	return false
}
