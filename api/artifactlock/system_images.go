package artifactlock

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"kordex.local/api/protocol"
)

const (
	SystemImagesLockHeader = "KORDEX-CUSTOMER-K3S-SYSTEM-IMAGES-LOCK-V1"
	SystemImagesDomain     = "kordex.customer-artifact-approval.k3s-system-images.v1\n"
	SystemImagesVersion    = "1"
	SystemImagesK3sVersion = "v1.36.6+k3s1"
	SystemImagesArch       = "linux/amd64"
	SystemImagesSourceURL  = "https://github.com/k3s-io/k3s/releases/download/v1.36.6%2Bk3s1/k3s-airgap-images-amd64.tar"
	SystemImagesBundleName = "k3s-airgap-images-amd64.tar"
	maxSystemImageLockSize = 64 << 10
	maxSystemImageBundle   = 512 << 20
	maxSystemImageEntries  = 10000
)

// k3sSystemImageReferences is copied from the pinned upstream source file
// scripts/airgap/image-list.txt at v1.36.6+k3s1. It defines names only; no
// digest or trust is implied. The customer signer approves the actual digests.
var k3sSystemImageReferences = []string{
	"docker.io/rancher/klipper-helm:v0.13.3-build20261021",
	"docker.io/rancher/klipper-lb:v0.4.17",
	"docker.io/rancher/local-path-provisioner:v0.0.37",
	"docker.io/rancher/mirrored-coredns-coredns:1.14.7",
	"docker.io/rancher/mirrored-library-busybox:1.37.0",
	"docker.io/rancher/mirrored-library-traefik:3.7.15",
	"docker.io/rancher/mirrored-metrics-server:v0.9.0",
	"docker.io/rancher/mirrored-pause:3.10.2",
}

type SystemImage struct {
	SourceReference string
	MirrorReference string
	Digest          string
}

type SystemImagesApprovalMetadata struct {
	BundleMirrorReference string
	ChecksumEvidenceRef   string
	AcquisitionReference  string
	ApprovalReference     string
	ApprovedBy            string
	ApprovedAt            string
}

// SystemImagesLock uses a fixed-order, line-based representation. The
// complete byte sequence is signed, avoiding JSON duplicate-key ambiguity.
type SystemImagesLock struct {
	ManifestVersion       string
	K3sVersion            string
	Architecture          string
	BundleName            string
	BundleAlgorithm       string
	BundleDigest          string
	SourceURL             string
	BundleMirrorReference string
	ChecksumEvidenceRef   string
	AcquisitionReference  string
	ApprovalReference     string
	ApprovedBy            string
	ApprovedAt            string
	SignerKeyID           string
	Images                []SystemImage
}

type VerifiedSystemImages struct {
	Lock         SystemImagesLock
	BundleDigest string
}

type imageInventory struct {
	K3sVersion   string        `json:"k3sVersion"`
	Architecture string        `json:"architecture"`
	BundleSHA256 string        `json:"bundleSha256"`
	Images       []imageRecord `json:"images"`
}

type imageRecord struct {
	SourceReference string `json:"sourceReference"`
	MirrorReference string `json:"mirrorReference"`
	Digest          string `json:"digest"`
}

var imageDigestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var imageHostPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?(?::[0-9]{1,5})?$`)
var imageHostLabelPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$`)
var approvalReferencePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+%-]{0,511}$`)

// CreateSystemImagesLock inspects an already acquired K3s OCI airgap archive
// and signs customer approval metadata using the existing artifact trust key.
// It does not download, execute, or claim upstream-authenticated artifacts.
func CreateSystemImagesLock(bundlePath, bundleMirrorURL, mirrorHost string, metadata SystemImagesApprovalMetadata, private ed25519.PrivateKey) ([]byte, []byte, error) {
	if len(private) != ed25519.PrivateKeySize || !private.Equal(ed25519.NewKeyFromSeed(private.Seed())) {
		return nil, nil, errors.New("invalid customer artifact signing key")
	}
	if bundleMirrorURL != metadata.BundleMirrorReference {
		return nil, nil, errors.New("system image bundle mirror URL differs from signed approval metadata")
	}
	digest, images, err := inspectSystemImageBundle(bundlePath, mirrorHost)
	if err != nil {
		return nil, nil, err
	}
	lock := SystemImagesLock{
		ManifestVersion: SystemImagesVersion, K3sVersion: SystemImagesK3sVersion,
		Architecture: SystemImagesArch, BundleName: SystemImagesBundleName,
		BundleAlgorithm: "sha256", BundleDigest: digest, SourceURL: SystemImagesSourceURL,
		BundleMirrorReference: metadata.BundleMirrorReference,
		ChecksumEvidenceRef:   metadata.ChecksumEvidenceRef,
		AcquisitionReference:  metadata.AcquisitionReference,
		ApprovalReference:     metadata.ApprovalReference,
		ApprovedBy:            metadata.ApprovedBy, ApprovedAt: metadata.ApprovedAt,
		SignerKeyID: protocol.KeyID(private.Public().(ed25519.PublicKey)),
		Images:      images,
	}
	if err := validateSystemImagesLock(lock); err != nil {
		return nil, nil, err
	}
	canonical := lock.Canonical()
	signature := base64.RawStdEncoding.EncodeToString(ed25519.Sign(private, append([]byte(SystemImagesDomain), canonical...))) + "\n"
	return canonical, []byte(signature), nil
}

// Canonical serializes every approval field and image row in fixed order.
func (l SystemImagesLock) Canonical() []byte {
	values := []string{
		SystemImagesLockHeader,
		"manifest_version=" + l.ManifestVersion,
		"k3s_version=" + l.K3sVersion,
		"architecture=" + l.Architecture,
		"bundle_name=" + l.BundleName,
		"bundle_algorithm=" + l.BundleAlgorithm,
		"bundle_digest=" + l.BundleDigest,
		"source_url=" + l.SourceURL,
		"bundle_mirror_reference=" + l.BundleMirrorReference,
		"checksum_evidence_ref=" + l.ChecksumEvidenceRef,
		"acquisition_reference=" + l.AcquisitionReference,
		"approval_reference=" + l.ApprovalReference,
		"approved_by=" + l.ApprovedBy,
		"approved_at=" + l.ApprovedAt,
		"signer_key_id=" + l.SignerKeyID,
		fmt.Sprintf("image_count=%d", len(l.Images)),
	}
	for _, image := range l.Images {
		values = append(values, "image="+image.SourceReference+"\t"+image.MirrorReference+"\t"+image.Digest)
	}
	return []byte(strings.Join(values, "\n") + "\n")
}

// VerifySystemImages authenticates the exact lock before using its bundle or
// per-image digests, then verifies every OCI manifest/config/layer blob.
func VerifySystemImages(lockBytes, signatureBytes, trustBytes []byte, bundlePath string) (VerifiedSystemImages, error) {
	lock, err := parseSystemImagesLock(lockBytes)
	if err != nil {
		return VerifiedSystemImages{}, err
	}
	keys, err := ParseTrust(trustBytes)
	if err != nil {
		return VerifiedSystemImages{}, err
	}
	public, ok := keys[lock.SignerKeyID]
	if !ok {
		return VerifiedSystemImages{}, errors.New("system image lock signer is not in the independently provisioned customer artifact trust bundle")
	}
	signature, err := parseArtifactSignature(signatureBytes)
	if err != nil {
		return VerifiedSystemImages{}, err
	}
	if !ed25519.Verify(public, append([]byte(SystemImagesDomain), lockBytes...), signature) {
		return VerifiedSystemImages{}, errors.New("K3s system image lock signature verification failed")
	}
	if err := validateSystemImagesLock(lock); err != nil {
		return VerifiedSystemImages{}, err
	}
	digest, images, err := inspectSystemImageBundle(bundlePath, imageHost(lock.Images[0].MirrorReference))
	if err != nil {
		return VerifiedSystemImages{}, err
	}
	if digest != lock.BundleDigest {
		return VerifiedSystemImages{}, errors.New("K3s system image bundle SHA-256 does not match the signed lock")
	}
	if len(images) != len(lock.Images) {
		return VerifiedSystemImages{}, errors.New("K3s system image bundle image count does not match the signed lock")
	}
	for i, actual := range images {
		if actual.SourceReference != lock.Images[i].SourceReference || actual.MirrorReference != lock.Images[i].MirrorReference || actual.Digest != lock.Images[i].Digest {
			return VerifiedSystemImages{}, fmt.Errorf("K3s system image %q does not match the signed reference mapping or digest", lock.Images[i].SourceReference)
		}
	}
	return VerifiedSystemImages{Lock: lock, BundleDigest: digest}, nil
}

func parseSystemImagesLock(data []byte) (SystemImagesLock, error) {
	if len(data) == 0 || len(data) > maxSystemImageLockSize || !bytes.HasSuffix(data, []byte("\n")) {
		return SystemImagesLock{}, errors.New("invalid K3s system image lock size or termination")
	}
	lines := strings.Split(string(data[:len(data)-1]), "\n")
	fieldNames := []string{"manifest_version", "k3s_version", "architecture", "bundle_name", "bundle_algorithm", "bundle_digest", "source_url", "bundle_mirror_reference", "checksum_evidence_ref", "acquisition_reference", "approval_reference", "approved_by", "approved_at", "signer_key_id", "image_count"}
	if len(lines) < len(fieldNames)+1 || lines[0] != SystemImagesLockHeader {
		return SystemImagesLock{}, errors.New("unsupported K3s system image lock format")
	}
	values := make([]string, len(fieldNames))
	for i, name := range fieldNames {
		prefix := name + "="
		if !strings.HasPrefix(lines[i+1], prefix) {
			return SystemImagesLock{}, fmt.Errorf("K3s system image lock field %q is missing, duplicated, or out of order", name)
		}
		values[i] = strings.TrimPrefix(lines[i+1], prefix)
		if values[i] == "" || strings.ContainsAny(values[i], "\r\x00") {
			return SystemImagesLock{}, fmt.Errorf("K3s system image lock field %q is malformed", name)
		}
	}
	count, err := parseBoundedDecimal(values[14], len(k3sSystemImageReferences))
	if err != nil || count != len(k3sSystemImageReferences) || len(lines) != len(fieldNames)+1+count {
		return SystemImagesLock{}, errors.New("K3s system image lock has an unsupported or incomplete image set")
	}
	lock := SystemImagesLock{
		ManifestVersion: values[0], K3sVersion: values[1], Architecture: values[2],
		BundleName: values[3], BundleAlgorithm: values[4], BundleDigest: values[5],
		SourceURL: values[6], BundleMirrorReference: values[7],
		ChecksumEvidenceRef: values[8], AcquisitionReference: values[9],
		ApprovalReference: values[10], ApprovedBy: values[11], ApprovedAt: values[12],
		SignerKeyID: values[13],
	}
	for _, line := range lines[len(fieldNames)+1:] {
		if !strings.HasPrefix(line, "image=") {
			return SystemImagesLock{}, errors.New("K3s system image lock contains an unexpected field")
		}
		parts := strings.Split(strings.TrimPrefix(line, "image="), "\t")
		if len(parts) != 3 {
			return SystemImagesLock{}, errors.New("malformed K3s system image mapping")
		}
		lock.Images = append(lock.Images, SystemImage{SourceReference: parts[0], MirrorReference: parts[1], Digest: parts[2]})
	}
	if !bytes.Equal(lock.Canonical(), data) {
		return SystemImagesLock{}, errors.New("K3s system image lock is not canonical")
	}
	return lock, nil
}

func validateSystemImagesLock(lock SystemImagesLock) error {
	if lock.ManifestVersion != SystemImagesVersion || lock.K3sVersion != SystemImagesK3sVersion || lock.Architecture != SystemImagesArch || lock.BundleName != SystemImagesBundleName || lock.BundleAlgorithm != "sha256" || lock.SourceURL != SystemImagesSourceURL {
		return errors.New("K3s system image lock does not match the supported manifest, version, architecture, bundle, or source")
	}
	if !digestPattern.MatchString(lock.BundleDigest) || !keyIDPattern.MatchString(lock.SignerKeyID) {
		return errors.New("K3s system image lock has an invalid bundle digest or signer ID")
	}
	for name, value := range map[string]string{
		"checksum evidence reference": lock.ChecksumEvidenceRef,
		"acquisition reference":       lock.AcquisitionReference,
		"approval reference":          lock.ApprovalReference,
		"approver":                    lock.ApprovedBy,
	} {
		if !approvalReferencePattern.MatchString(value) || strings.Contains(value, "..") || strings.HasPrefix(value, "/") {
			return fmt.Errorf("invalid K3s system image %s", name)
		}
	}
	if err := validateMirrorURL(lock.BundleMirrorReference); err != nil {
		return fmt.Errorf("invalid K3s system image bundle mirror reference: %w", err)
	}
	bundleURL, _ := url.Parse(lock.BundleMirrorReference)
	expectedBundlePath := "/" + path.Join("k3s", SystemImagesK3sVersion, "linux-amd64", lock.BundleDigest, SystemImagesBundleName)
	if !strings.HasSuffix(bundleURL.Path, expectedBundlePath) {
		return errors.New("K3s system image bundle URL must identify the content-addressed staged bundle path")
	}
	approvedAt, err := time.Parse(time.RFC3339Nano, lock.ApprovedAt)
	if err != nil || !strings.HasSuffix(lock.ApprovedAt, "Z") || approvedAt.UTC().Format(time.RFC3339Nano) != lock.ApprovedAt {
		return errors.New("K3s system image approval time must be canonical UTC RFC3339")
	}
	if len(lock.Images) != len(k3sSystemImageReferences) {
		return errors.New("K3s system image lock must contain the exact pinned image list")
	}
	host := ""
	for i, image := range lock.Images {
		if image.SourceReference != k3sSystemImageReferences[i] || !imageDigestPattern.MatchString(image.Digest) {
			return fmt.Errorf("K3s system image %d has an unexpected source reference or invalid digest", i)
		}
		mirror, err := parseImageReference(image.MirrorReference)
		if err != nil {
			return fmt.Errorf("invalid private mirror image reference for %q", image.SourceReference)
		}
		source, _ := parseImageReference(image.SourceReference)
		if mirror.pathAndTag != source.pathAndTag {
			return fmt.Errorf("private mirror image reference for %q must preserve its repository path and tag", image.SourceReference)
		}
		if host == "" {
			host = mirror.host
		} else if host != mirror.host {
			return errors.New("all K3s system images must use one private mirror host")
		}
	}
	if isPublicImageRegistry(host) {
		return errors.New("K3s system images must use a customer-controlled private registry host")
	}
	return nil
}

func isPublicImageRegistry(host string) bool {
	name := strings.TrimSuffix(host, ":443")
	switch strings.ToLower(name) {
	case "docker.io", "registry-1.docker.io", "ghcr.io", "quay.io":
		return true
	default:
		return false
	}
}

func validateMirrorURL(value string) error {
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("expected traversal-free HTTPS URL without credentials, query, or fragment")
	}
	if err := validateRegistryHost(u.Host); err != nil {
		return errors.New("invalid HTTPS mirror host")
	}
	if u.Port() != "" && u.Port() != "443" {
		return errors.New("HTTPS artifact mirrors must use TCP/443")
	}
	decodedPath, err := url.PathUnescape(u.EscapedPath())
	if err != nil || strings.Contains(decodedPath, "%") || path.Clean(decodedPath) != decodedPath || pathHasTraversal(decodedPath) {
		return errors.New("expected traversal-free HTTPS URL without credentials, query, or fragment")
	}
	return nil
}

type parsedImageReference struct{ host, pathAndTag string }

func parseImageReference(value string) (parsedImageReference, error) {
	if strings.ContainsAny(value, "\r\n\t @") || strings.Count(value, "/") < 2 {
		return parsedImageReference{}, errors.New("invalid image reference")
	}
	firstSlash := strings.IndexByte(value, '/')
	if firstSlash <= 0 {
		return parsedImageReference{}, errors.New("image reference lacks a registry")
	}
	host := value[:firstSlash]
	if err := validateRegistryHost(host); err != nil {
		return parsedImageReference{}, errors.New("invalid image registry host")
	}
	pathAndTag := value[firstSlash+1:]
	if strings.Contains(pathAndTag, "..") || strings.Contains(pathAndTag, "//") || strings.ContainsAny(pathAndTag, "\\?#") {
		return parsedImageReference{}, errors.New("unsafe image repository reference")
	}
	lastSlash := strings.LastIndexByte(pathAndTag, '/')
	colon := strings.LastIndexByte(pathAndTag, ':')
	if colon <= lastSlash+1 || colon == len(pathAndTag)-1 {
		return parsedImageReference{}, errors.New("image reference must include a tag")
	}
	return parsedImageReference{host: host, pathAndTag: pathAndTag}, nil
}

func validateRegistryHost(host string) error {
	if !imageHostPattern.MatchString(host) {
		return errors.New("invalid registry host syntax")
	}
	name := host
	if strings.Contains(host, ":") {
		parsedHost, portText, err := net.SplitHostPort(host)
		if err != nil || parsedHost == "" {
			return errors.New("invalid registry host port")
		}
		port, err := strconv.Atoi(portText)
		if err != nil || port != 443 {
			return errors.New("private registry must use TCP/443")
		}
		name = parsedHost
	}
	if len(name) > 253 {
		return errors.New("registry DNS name is too long")
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || !imageHostLabelPattern.MatchString(label) {
			return errors.New("invalid registry DNS label")
		}
	}
	return nil
}

func imageHost(reference string) string {
	parsed, _ := parseImageReference(reference)
	return parsed.host
}

func parseArtifactSignature(data []byte) ([]byte, error) {
	text := string(data)
	if len(data) > 128 || !strings.HasSuffix(text, "\n") || strings.ContainsAny(strings.TrimSuffix(text, "\n"), "\r\n") {
		return nil, errors.New("malformed K3s system image signature")
	}
	signature, err := base64.RawStdEncoding.DecodeString(strings.TrimSuffix(text, "\n"))
	if err != nil || len(signature) != ed25519.SignatureSize || base64.RawStdEncoding.EncodeToString(signature) != strings.TrimSuffix(text, "\n") {
		return nil, errors.New("malformed K3s system image signature")
	}
	return signature, nil
}

func parseBoundedDecimal(value string, max int) (int, error) {
	if value == "" || (len(value) > 1 && value[0] == '0') {
		return 0, errors.New("noncanonical number")
	}
	n := 0
	for _, char := range value {
		if char < '0' || char > '9' {
			return 0, errors.New("invalid number")
		}
		n = n*10 + int(char-'0')
		if n > max {
			return 0, errors.New("number too large")
		}
	}
	return n, nil
}

type ociLayout struct {
	ImageLayoutVersion string `json:"imageLayoutVersion"`
}
type ociDescriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Platform    *ociPlatform      `json:"platform,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}
type ociPlatform struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
}
type ociIndex struct {
	SchemaVersion int             `json:"schemaVersion"`
	MediaType     string          `json:"mediaType"`
	Manifests     []ociDescriptor `json:"manifests"`
}
type ociManifest struct {
	SchemaVersion int             `json:"schemaVersion"`
	MediaType     string          `json:"mediaType"`
	Config        ociDescriptor   `json:"config"`
	Layers        []ociDescriptor `json:"layers"`
}
type ociConfig struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
}

func inspectSystemImageBundle(bundlePath, mirrorHost string) (string, []SystemImage, error) {
	info, err := os.Lstat(bundlePath)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxSystemImageBundle {
		return "", nil, errors.New("K3s system image bundle must be a bounded regular file")
	}
	file, err := os.Open(bundlePath)
	if err != nil {
		return "", nil, errors.New("K3s system image bundle is unavailable")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxSystemImageBundle+1))
	after, statErr := file.Stat()
	if err != nil || statErr != nil || int64(len(data)) != info.Size() || !os.SameFile(info, after) || !after.ModTime().Equal(info.ModTime()) {
		return "", nil, errors.New("K3s system image bundle changed while being read")
	}
	archiveDigest := sha256.Sum256(data)
	blobs := map[string][]byte{}
	files := map[string]bool{}
	reader := tar.NewReader(bytes.NewReader(data))
	for count := 0; ; count++ {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", nil, errors.New("invalid K3s OCI image archive")
		}
		if count >= maxSystemImageEntries || header.Size < 0 || header.Size > maxSystemImageBundle {
			return "", nil, errors.New("K3s OCI image archive has unsupported entries")
		}
		name := strings.TrimSuffix(header.Name, "/")
		clean := path.Clean(name)
		if name == "" || clean != name || strings.HasPrefix(name, "../") || strings.HasPrefix(name, "/") || files[name] {
			return "", nil, errors.New("K3s OCI image archive has an unsafe or duplicate path")
		}
		if header.Typeflag == tar.TypeDir {
			if header.Size != 0 || (name != "blobs" && name != "blobs/sha256") {
				return "", nil, errors.New("K3s OCI image archive has an unexpected directory")
			}
			files[name] = true
			continue
		}
		if header.Typeflag != tar.TypeReg {
			return "", nil, errors.New("K3s OCI image archive contains a non-regular file")
		}
		files[name] = true
		content, err := io.ReadAll(io.LimitReader(reader, header.Size+1))
		if err != nil || int64(len(content)) != header.Size {
			return "", nil, errors.New("truncated K3s OCI image archive entry")
		}
		if strings.HasPrefix(name, "blobs/sha256/") {
			blobs[strings.TrimPrefix(name, "blobs/sha256/")] = content
		} else if name != "oci-layout" && name != "index.json" {
			return "", nil, fmt.Errorf("unexpected file in K3s OCI image archive: %s", name)
		}
	}
	if !files["oci-layout"] || !files["index.json"] {
		return "", nil, errors.New("K3s OCI archive is missing oci-layout or index.json")
	}
	var layout ociLayout
	if err := json.Unmarshal(extractArchiveFile(data, "oci-layout"), &layout); err != nil || layout.ImageLayoutVersion != "1.0.0" {
		return "", nil, errors.New("unsupported K3s OCI layout version")
	}
	var index ociIndex
	if err := json.Unmarshal(extractArchiveFile(data, "index.json"), &index); err != nil || index.SchemaVersion != 2 || len(index.Manifests) != len(k3sSystemImageReferences) {
		return "", nil, errors.New("K3s OCI index does not contain the exact required image set")
	}
	// OCI permits the index mediaType field to be omitted. When a producer
	// declares it, reject conflicting formats instead of treating any JSON
	// object with a manifests array as an OCI index.
	if index.MediaType != "" && index.MediaType != "application/vnd.oci.image.index.v1+json" {
		return "", nil, errors.New("K3s OCI index declares an unsupported media type")
	}
	imageByRef := make(map[string]SystemImage, len(index.Manifests))
	usedBlobs := map[string]bool{}
	for _, descriptor := range index.Manifests {
		if descriptor.MediaType != "" && descriptor.MediaType != "application/vnd.oci.image.manifest.v1+json" {
			return "", nil, errors.New("K3s OCI index contains an unsupported image descriptor media type")
		}
		ref := descriptor.Annotations["org.opencontainers.image.ref.name"]
		if ref == "" {
			return "", nil, errors.New("OCI image descriptor lacks its source reference")
		}
		if _, expected := expectedSystemImage(ref); !expected {
			return "", nil, fmt.Errorf("unexpected K3s image in bundle: %s", ref)
		}
		if _, duplicate := imageByRef[ref]; duplicate {
			return "", nil, fmt.Errorf("duplicate K3s image in bundle: %s", ref)
		}
		if descriptor.Platform != nil && (descriptor.Platform.OS != "linux" || descriptor.Platform.Architecture != "amd64") {
			return "", nil, fmt.Errorf("K3s image %s has the wrong platform", ref)
		}
		manifestBytes, err := verifiedBlob(blobs, descriptor, usedBlobs)
		if err != nil {
			return "", nil, err
		}
		var manifest ociManifest
		if err := json.Unmarshal(manifestBytes, &manifest); err != nil || manifest.SchemaVersion != 2 {
			return "", nil, fmt.Errorf("invalid OCI manifest for %s", ref)
		}
		if manifest.MediaType != "" && manifest.MediaType != "application/vnd.oci.image.manifest.v1+json" {
			return "", nil, fmt.Errorf("K3s image %s declares an unsupported OCI manifest media type", ref)
		}
		if manifest.Config.MediaType != "" && manifest.Config.MediaType != "application/vnd.oci.image.config.v1+json" {
			return "", nil, fmt.Errorf("K3s image %s declares an unsupported OCI config media type", ref)
		}
		configBytes, err := verifiedBlob(blobs, manifest.Config, usedBlobs)
		if err != nil {
			return "", nil, err
		}
		var config ociConfig
		if err := json.Unmarshal(configBytes, &config); err != nil || config.OS != "linux" || config.Architecture != "amd64" {
			return "", nil, fmt.Errorf("K3s image %s config is not linux/amd64", ref)
		}
		for _, layer := range manifest.Layers {
			if _, err := verifiedBlob(blobs, layer, usedBlobs); err != nil {
				return "", nil, err
			}
		}
		source, _ := parseImageReference(ref)
		mirror := mirrorHost + "/" + source.pathAndTag
		imageByRef[ref] = SystemImage{SourceReference: ref, MirrorReference: mirror, Digest: descriptor.Digest}
	}
	images := make([]SystemImage, 0, len(k3sSystemImageReferences))
	for _, ref := range k3sSystemImageReferences {
		image, ok := imageByRef[ref]
		if !ok {
			return "", nil, fmt.Errorf("required K3s image is missing: %s", ref)
		}
		images = append(images, image)
	}
	for digest := range blobs {
		if !usedBlobs[digest] {
			return "", nil, errors.New("K3s OCI archive contains an unreferenced image blob")
		}
	}
	return hex.EncodeToString(archiveDigest[:]), images, nil
}

func extractArchiveFile(data []byte, wanted string) []byte {
	reader := tar.NewReader(bytes.NewReader(data))
	for {
		header, err := reader.Next()
		if err != nil {
			return nil
		}
		if header.Name == wanted {
			result, _ := io.ReadAll(io.LimitReader(reader, header.Size+1))
			return result
		}
	}
}

func verifiedBlob(blobs map[string][]byte, descriptor ociDescriptor, used map[string]bool) ([]byte, error) {
	if !imageDigestPattern.MatchString(descriptor.Digest) || descriptor.Size < 0 {
		return nil, errors.New("invalid OCI blob descriptor")
	}
	encoded := strings.TrimPrefix(descriptor.Digest, "sha256:")
	content, ok := blobs[encoded]
	if !ok || int64(len(content)) != descriptor.Size {
		return nil, errors.New("required K3s image blob is missing or has the wrong size")
	}
	digest := sha256.Sum256(content)
	if hex.EncodeToString(digest[:]) != encoded {
		return nil, errors.New("K3s image blob digest mismatch")
	}
	used[encoded] = true
	return content, nil
}

func expectedSystemImage(ref string) (int, bool) {
	for i, expected := range k3sSystemImageReferences {
		if ref == expected {
			return i, true
		}
	}
	return 0, false
}

// StageSystemImages publishes a verified immutable bundle directory using an
// atomic rename. Existing identical output is idempotent; conflicting output
// is rejected and never overwritten.
func StageSystemImages(lockBytes, signatureBytes, trustBytes []byte, bundlePath, outputRoot string) (string, VerifiedSystemImages, error) {
	verified, err := VerifySystemImages(lockBytes, signatureBytes, trustBytes, bundlePath)
	if err != nil {
		return "", VerifiedSystemImages{}, err
	}
	if verified.BundleDigest != verified.Lock.BundleDigest {
		return "", VerifiedSystemImages{}, errors.New("verified K3s image bundle state is inconsistent")
	}
	rootInfo, err := os.Lstat(outputRoot)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return "", VerifiedSystemImages{}, errors.New("private image mirror staging root must be an existing real directory")
	}
	root, err := filepath.EvalSymlinks(outputRoot)
	if err != nil {
		return "", VerifiedSystemImages{}, errors.New("private image mirror staging root is unsafe")
	}
	destination := filepath.Join(root, "k3s", SystemImagesK3sVersion, "linux-amd64", verified.BundleDigest)
	if _, err := os.Lstat(destination); err == nil {
		if err := verifyStagedDirectory(destination, verified.BundleDigest, lockBytes, signatureBytes); err != nil {
			return "", VerifiedSystemImages{}, errors.New("existing private image mirror entry conflicts with verified bundle")
		}
		return destination, verified, nil
	} else if !os.IsNotExist(err) {
		return "", VerifiedSystemImages{}, errors.New("could not inspect private image mirror destination")
	}
	parent := filepath.Dir(destination)
	current := root
	for _, component := range []string{"k3s", SystemImagesK3sVersion, "linux-amd64"} {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			if err := os.Mkdir(current, 0755); err != nil {
				return "", VerifiedSystemImages{}, errors.New("could not create private image mirror path")
			}
			continue
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", VerifiedSystemImages{}, errors.New("private image mirror path contains an unsafe component")
		}
	}
	temp, err := os.MkdirTemp(parent, ".k3s-images-stage-")
	if err != nil {
		return "", VerifiedSystemImages{}, errors.New("could not create private image mirror staging directory")
	}
	defer os.RemoveAll(temp)
	if err := os.Chmod(temp, 0755); err != nil {
		return "", VerifiedSystemImages{}, errors.New("could not set staging directory permissions")
	}
	for name, content := range map[string][]byte{SystemImagesBundleName: nil, "k3s-system-images.lock": lockBytes, "k3s-system-images.lock.sig": signatureBytes} {
		path := filepath.Join(temp, name)
		if name == SystemImagesBundleName {
			if err := copyRegularFile(bundlePath, path, 0644, maxSystemImageBundle); err != nil {
				return "", VerifiedSystemImages{}, err
			}
		} else if err := writeNewFile(path, content, 0644); err != nil {
			return "", VerifiedSystemImages{}, errors.New("could not stage signed K3s image lock")
		}
	}
	if err := writeNewFile(filepath.Join(temp, "registries.yaml"), verified.Lock.RegistryConfig(), 0644); err != nil {
		return "", VerifiedSystemImages{}, errors.New("could not stage private K3s registry configuration")
	}
	inventory := imageInventory{K3sVersion: verified.Lock.K3sVersion, Architecture: verified.Lock.Architecture, BundleSHA256: verified.BundleDigest, Images: make([]imageRecord, 0, len(verified.Lock.Images))}
	for _, image := range verified.Lock.Images {
		inventory.Images = append(inventory.Images, imageRecord{image.SourceReference, image.MirrorReference, image.Digest})
	}
	encodedInventory, _ := json.MarshalIndent(inventory, "", "  ")
	if err := writeNewFile(filepath.Join(temp, "inventory.json"), append(encodedInventory, '\n'), 0644); err != nil {
		return "", VerifiedSystemImages{}, errors.New("could not stage verified image inventory")
	}
	if err := verifyStagedDirectory(temp, verified.BundleDigest, lockBytes, signatureBytes); err != nil {
		return "", VerifiedSystemImages{}, errors.New("staged K3s system image bundle failed verification")
	}
	if err := os.Rename(temp, destination); err != nil {
		if existingErr := verifyStagedDirectory(destination, verified.BundleDigest, lockBytes, signatureBytes); existingErr == nil {
			return destination, verified, nil
		}
		return "", VerifiedSystemImages{}, errors.New("could not atomically publish private K3s image bundle")
	}
	return destination, verified, nil
}

func verifyStagedDirectory(directory, bundleDigest string, lockBytes, signatureBytes []byte) error {
	dirInfo, err := os.Lstat(directory)
	if err != nil || !dirInfo.IsDir() || dirInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("staged image directory is unsafe")
	}
	for name, expected := range map[string][]byte{
		"k3s-system-images.lock":     lockBytes,
		"k3s-system-images.lock.sig": signatureBytes,
		"registries.yaml":            mustRegistryConfig(lockBytes),
	} {
		if expected == nil {
			return errors.New("staged registry configuration cannot be derived from the signed lock")
		}
		path := filepath.Join(directory, name)
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("staged trust material is unsafe")
		}
		actual, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(actual, expected) {
			return errors.New("staged trust material mismatch")
		}
	}
	lock, err := parseSystemImagesLock(lockBytes)
	if err != nil {
		return err
	}
	inventory := imageInventory{K3sVersion: lock.K3sVersion, Architecture: lock.Architecture, BundleSHA256: lock.BundleDigest, Images: make([]imageRecord, 0, len(lock.Images))}
	for _, image := range lock.Images {
		inventory.Images = append(inventory.Images, imageRecord{image.SourceReference, image.MirrorReference, image.Digest})
	}
	wantInventory, _ := json.MarshalIndent(inventory, "", "  ")
	wantInventory = append(wantInventory, '\n')
	inventoryPath := filepath.Join(directory, "inventory.json")
	inventoryInfo, err := os.Lstat(inventoryPath)
	if err != nil || !inventoryInfo.Mode().IsRegular() || inventoryInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("staged image inventory is missing or unsafe")
	}
	actualInventory, err := os.ReadFile(inventoryPath)
	if err != nil || !bytes.Equal(actualInventory, wantInventory) {
		return errors.New("staged image inventory does not match the signed lock")
	}
	bundle := filepath.Join(directory, SystemImagesBundleName)
	bundleInfo, err := os.Lstat(bundle)
	if err != nil || !bundleInfo.Mode().IsRegular() || bundleInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("staged image bundle is missing or unsafe")
	}
	file, err := os.Open(bundle)
	if err != nil {
		return err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil || hex.EncodeToString(hash.Sum(nil)) != bundleDigest {
		return errors.New("staged bundle digest mismatch")
	}
	return nil
}

func mustRegistryConfig(lockBytes []byte) []byte {
	lock, err := parseSystemImagesLock(lockBytes)
	if err != nil || validateSystemImagesLock(lock) != nil {
		return nil
	}
	return lock.RegistryConfig()
}

func copyRegularFile(sourcePath, destinationPath string, mode os.FileMode, limit int64) error {
	info, err := os.Lstat(sourcePath)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit {
		return errors.New("K3s image bundle source is unsafe")
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		return errors.New("K3s image bundle is unavailable")
	}
	defer source.Close()
	initial, err := source.Stat()
	if err != nil || !os.SameFile(info, initial) {
		return errors.New("K3s image bundle changed before staging")
	}
	dest, err := os.OpenFile(destinationPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return errors.New("could not create staged K3s image bundle")
	}
	_, copyErr := io.Copy(dest, io.LimitReader(source, limit+1))
	syncErr := dest.Sync()
	closeErr := dest.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil {
		return errors.New("could not write staged K3s image bundle")
	}
	after, err := source.Stat()
	if err != nil || !os.SameFile(info, after) || !after.ModTime().Equal(info.ModTime()) {
		return errors.New("K3s image bundle changed while staging")
	}
	return nil
}

func writeNewFile(path string, content []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(content); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

// InventoryJSON emits a deterministic public inventory of the verified image set.
func (v VerifiedSystemImages) InventoryJSON() ([]byte, error) {
	inventory := imageInventory{K3sVersion: v.Lock.K3sVersion, Architecture: v.Lock.Architecture, BundleSHA256: v.BundleDigest, Images: make([]imageRecord, 0, len(v.Lock.Images))}
	for _, image := range v.Lock.Images {
		inventory.Images = append(inventory.Images, imageRecord{image.SourceReference, image.MirrorReference, image.Digest})
	}
	return json.MarshalIndent(inventory, "", "  ")
}

// SortedPrivateReferences is used to write deterministic K3s registry config.
func (l SystemImagesLock) SortedPrivateReferences() []string {
	refs := make([]string, 0, len(l.Images))
	for _, image := range l.Images {
		refs = append(refs, image.MirrorReference)
	}
	sort.Strings(refs)
	return refs
}

// PrivateMirrorHost returns the single customer registry host bound into the
// lock. Validation ensures every image preserves its source repository/tag.
func (l SystemImagesLock) PrivateMirrorHost() string {
	if len(l.Images) == 0 {
		return ""
	}
	return imageHost(l.Images[0].MirrorReference)
}

// RegistryConfig emits the exact K3s registry mapping for the signed mirror.
// The public default endpoint is separately disabled on every K3s node.
func (l SystemImagesLock) RegistryConfig() []byte {
	return []byte("mirrors:\n  docker.io:\n    endpoint:\n      - \"https://" + l.PrivateMirrorHost() + "\"\n")
}
