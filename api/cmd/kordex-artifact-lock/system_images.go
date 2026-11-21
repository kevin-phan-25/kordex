package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"kordex.local/api/artifactlock"
	"kordex.local/api/protocol"
)

func systemImages(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: kordex-artifact-lock system-images sign|verify|stage [flags]")
	}
	switch args[0] {
	case "sign":
		return signSystemImages(args[1:])
	case "verify":
		return verifySystemImages(args[1:])
	case "stage":
		return stageSystemImages(args[1:])
	default:
		return errors.New("expected system-images sign, verify, or stage")
	}
}

func signSystemImages(args []string) error {
	flags := flag.NewFlagSet("system-images sign", flag.ContinueOnError)
	bundle := flags.String("bundle", "", "already acquired K3s airgap OCI archive")
	privateFile := flags.String("private-key-file", "", "existing customer artifact Ed25519 seed file (0600)")
	trustFile := flags.String("trust-bundle", "", "independently provisioned customer artifact public-key bundle")
	bundleMirror := flags.String("bundle-mirror-url", "", "exact private HTTPS URL for the verified K3s image archive")
	mirrorRegistry := flags.String("mirror-registry", "", "private registry host that preserves image repository paths")
	checksumEvidence := flags.String("checksum-evidence-ref", "", "customer evidence record for archive/image digest review")
	acquisition := flags.String("acquisition-ref", "", "customer acquisition record reference")
	approval := flags.String("approval-ref", "", "customer approval record reference")
	approvedBy := flags.String("approved-by", "", "customer approver identity/reference")
	approvedAt := flags.String("approved-at", "", "approval time in UTC RFC3339")
	lockPath := flags.String("lock-out", "", "new signed image manifest output path")
	signaturePath := flags.String("signature-out", "", "new detached signature output path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *bundle == "" || *privateFile == "" || *trustFile == "" || *bundleMirror == "" || *mirrorRegistry == "" || *checksumEvidence == "" || *acquisition == "" || *approval == "" || *approvedBy == "" || *approvedAt == "" || *lockPath == "" || *signaturePath == "" {
		return errors.New("system-images sign requires bundle, existing signing key, independent trust, mirror references, approval metadata, and new output paths")
	}
	lockAbs, err := filepath.Abs(*lockPath)
	if err != nil {
		return errors.New("invalid system image lock output path")
	}
	sigAbs, err := filepath.Abs(*signaturePath)
	if err != nil || lockAbs == sigAbs {
		return errors.New("system image lock and signature output paths must differ")
	}
	private, err := readPrivateSeed(*privateFile)
	if err != nil {
		return err
	}
	trustBytes, err := readPublicFile(*trustFile, 16<<10)
	if err != nil {
		return err
	}
	trusted, err := artifactlock.ParseTrust(trustBytes)
	if err != nil {
		return err
	}
	keyID := protocol.KeyID(private.Public().(ed25519.PublicKey))
	if _, ok := trusted[keyID]; !ok {
		return errors.New("signing key is not in the independently provisioned customer artifact trust bundle")
	}
	parsedApprovalTime, err := time.Parse(time.RFC3339Nano, *approvedAt)
	if err != nil || !strings.HasSuffix(*approvedAt, "Z") || parsedApprovalTime.UTC().Format(time.RFC3339Nano) != *approvedAt {
		return errors.New("approved-at must be canonical UTC RFC3339")
	}
	metadata := artifactlock.SystemImagesApprovalMetadata{
		BundleMirrorReference: *bundleMirror, ChecksumEvidenceRef: *checksumEvidence,
		AcquisitionReference: *acquisition, ApprovalReference: *approval,
		ApprovedBy: *approvedBy, ApprovedAt: *approvedAt,
	}
	lock, signature, err := artifactlock.CreateSystemImagesLock(*bundle, *bundleMirror, *mirrorRegistry, metadata, private)
	if err != nil {
		return err
	}
	if err := writePairNew(lockAbs, lock, sigAbs, signature); err != nil {
		return err
	}
	fmt.Printf("Signed customer-approved K3s system image manifest; key ID %s. No upstream provenance claim is made.\n", keyID)
	return nil
}

func verifySystemImages(args []string) error {
	flags := flag.NewFlagSet("system-images verify", flag.ContinueOnError)
	bundle := flags.String("bundle", "", "local customer-approved K3s airgap image archive")
	lockPath := flags.String("lock", "", "customer-signed K3s system image lock")
	signaturePath := flags.String("signature", "", "detached system image lock signature")
	trustPath := flags.String("trust-bundle", "", "independently provisioned customer artifact public-key bundle")
	jsonOutput := flags.Bool("json", false, "emit verified lock fields as JSON for the guarded lab helper")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *bundle == "" || *lockPath == "" || *signaturePath == "" || *trustPath == "" {
		return errors.New("system-images verify requires bundle, lock, signature, and independent trust bundle paths")
	}
	lockBytes, err := readPublicFile(*lockPath, 64<<10)
	if err != nil {
		return err
	}
	signatureBytes, err := readPublicFile(*signaturePath, 4096)
	if err != nil {
		return err
	}
	trustBytes, err := readPublicFile(*trustPath, 16<<10)
	if err != nil {
		return err
	}
	verified, err := artifactlock.VerifySystemImages(lockBytes, signatureBytes, trustBytes, *bundle)
	if err != nil {
		return err
	}
	if *jsonOutput {
		result := struct {
			ManifestVersion string `json:"manifestVersion"`
			K3sVersion      string `json:"k3sVersion"`
			Architecture    string `json:"architecture"`
			BundleSHA256    string `json:"bundleSha256"`
			BundleURL       string `json:"bundleMirrorReference"`
			MirrorHost      string `json:"mirrorHost"`
			SignerKeyID     string `json:"signerKeyId"`
		}{verified.Lock.ManifestVersion, verified.Lock.K3sVersion, verified.Lock.Architecture,
			verified.BundleDigest, verified.Lock.BundleMirrorReference, verified.Lock.PrivateMirrorHost(), verified.Lock.SignerKeyID}
		return json.NewEncoder(os.Stdout).Encode(result)
	}
	fmt.Printf("Verified customer-approved K3s %s %s image bundle sha256:%s signer=%s images=%d\n",
		verified.Lock.K3sVersion, verified.Lock.Architecture, verified.BundleDigest, verified.Lock.SignerKeyID, len(verified.Lock.Images))
	return nil
}

func stageSystemImages(args []string) error {
	flags := flag.NewFlagSet("system-images stage", flag.ContinueOnError)
	bundle := flags.String("bundle", "", "local customer-approved K3s airgap image archive")
	lockPath := flags.String("lock", "", "customer-signed K3s system image lock")
	signaturePath := flags.String("signature", "", "detached system image lock signature")
	trustPath := flags.String("trust-bundle", "", "independently provisioned customer artifact public-key bundle")
	outputRoot := flags.String("output-root", "", "existing directory backed by the customer private artifact mirror")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *bundle == "" || *lockPath == "" || *signaturePath == "" || *trustPath == "" || *outputRoot == "" {
		return errors.New("system-images stage requires bundle, lock, signature, independent trust, and private mirror output root")
	}
	lockBytes, err := readPublicFile(*lockPath, 64<<10)
	if err != nil {
		return err
	}
	signatureBytes, err := readPublicFile(*signaturePath, 4096)
	if err != nil {
		return err
	}
	trustBytes, err := readPublicFile(*trustPath, 16<<10)
	if err != nil {
		return err
	}
	destination, verified, err := artifactlock.StageSystemImages(lockBytes, signatureBytes, trustBytes, *bundle, *outputRoot)
	if err != nil {
		return err
	}
	fmt.Printf("Staged verified K3s %s %s image bundle sha256:%s at %s (images=%d)\n",
		verified.Lock.K3sVersion, verified.Lock.Architecture, verified.BundleDigest, destination, len(verified.Lock.Images))
	fmt.Printf("Private K3s registry configuration: %s\n", filepath.Join(destination, "registries.yaml"))
	return nil
}
