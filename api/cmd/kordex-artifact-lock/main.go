// kordex-artifact-lock signs or verifies a customer-approved K3s artifact lock.
// It never generates keys or downloads artifacts.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"kordex.local/api/artifactlock"
	"kordex.local/api/protocol"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: kordex-artifact-lock sign|verify|system-images [flags]")
	}
	switch args[0] {
	case "sign":
		return sign(args[1:])
	case "verify":
		return verify(args[1:])
	case "trust-export":
		return trustExport(args[1:])
	case "system-images":
		return systemImages(args[1:])
	default:
		return errors.New("expected sign, verify, trust-export, or system-images")
	}
}

func trustExport(args []string) error {
	flags := flag.NewFlagSet("trust-export", flag.ContinueOnError)
	privateFile := flags.String("private-key-file", "", "existing customer artifact Ed25519 seed file (0600)")
	priorPath := flags.String("prior-trust-bundle", "", "optional previously approved customer artifact trust bundle for rotation overlap")
	output := flags.String("trust-out", "", "new public trust bundle output path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *privateFile == "" || *output == "" {
		return errors.New("trust-export requires an existing private key file and a new trust output path")
	}
	private, err := readPrivateSeed(*privateFile)
	if err != nil {
		return err
	}
	keys := make(map[string]ed25519.PublicKey)
	if *priorPath != "" {
		data, err := readPublicFile(*priorPath, 16<<10)
		if err != nil {
			return err
		}
		keys, err = artifactlock.ParseTrust(data)
		if err != nil {
			return err
		}
	}
	public := private.Public().(ed25519.PublicKey)
	keyID := protocol.KeyID(public)
	keys[keyID] = public
	bundle, err := artifactlock.EncodeTrust(keys)
	if err != nil {
		return err
	}
	path, err := filepath.Abs(*output)
	if err != nil {
		return errors.New("invalid trust output path")
	}
	if err := writeNew(path, bundle, 0644); err != nil {
		return errors.New("trust output must be a new file and writable")
	}
	fmt.Printf("Wrote public customer artifact trust bundle; key ID %s. Independently confirm this ID before trusting it.\n", keyID)
	return nil
}

func sign(args []string) error {
	flags := flag.NewFlagSet("sign", flag.ContinueOnError)
	binary := flags.String("binary", "", "already acquired local K3s binary")
	privateFile := flags.String("private-key-file", "", "existing customer Ed25519 seed file (0600)")
	trustFile := flags.String("trust-bundle", "", "independently provisioned customer artifact public-key bundle")
	mirror := flags.String("mirror-url", "", "approved internal HTTPS mirror URL")
	checksumEvidence := flags.String("checksum-evidence-ref", "", "customer evidence record for acquisition/checksum review")
	acquisition := flags.String("acquisition-ref", "", "customer acquisition record reference")
	approval := flags.String("approval-ref", "", "customer approval record reference")
	approvedBy := flags.String("approved-by", "", "customer approver identity/reference")
	approvedAt := flags.String("approved-at", "", "approval time in UTC RFC3339")
	lockPath := flags.String("lock-out", "", "new artifact lock output path")
	signaturePath := flags.String("signature-out", "", "new detached signature output path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *binary == "" || *privateFile == "" || *trustFile == "" || *mirror == "" || *checksumEvidence == "" || *acquisition == "" || *approval == "" || *approvedBy == "" || *approvedAt == "" || *lockPath == "" || *signaturePath == "" {
		return errors.New("sign requires binary, existing private key, independent trust bundle, approval metadata, mirror URL, and new output paths")
	}
	lockAbs, err := filepath.Abs(*lockPath)
	if err != nil {
		return errors.New("invalid lock output path")
	}
	sigAbs, err := filepath.Abs(*signaturePath)
	if err != nil || lockAbs == sigAbs {
		return errors.New("lock and signature output paths must differ")
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
	public := private.Public().(ed25519.PublicKey)
	keyID := protocol.KeyID(public)
	if _, ok := trusted[keyID]; !ok {
		return errors.New("signing key is not present in the independently provisioned customer artifact trust bundle")
	}
	parsedApprovalTime, err := time.Parse(time.RFC3339Nano, *approvedAt)
	if err != nil || !strings.HasSuffix(*approvedAt, "Z") || parsedApprovalTime.UTC().Format(time.RFC3339Nano) != *approvedAt {
		return errors.New("approved-at must be canonical UTC RFC3339")
	}
	lock, signature, err := artifactlock.CreateK3sLock(*binary, artifactlock.ApprovalMetadata{
		MirrorReference: *mirror, ChecksumEvidenceRef: *checksumEvidence,
		AcquisitionReference: *acquisition, ApprovalReference: *approval,
		ApprovedBy: *approvedBy, ApprovedAt: *approvedAt,
	}, private)
	if err != nil {
		return err
	}
	if err := writePairNew(lockAbs, lock, sigAbs, signature); err != nil {
		return err
	}
	fmt.Printf("Signed customer-approved K3s lock; key ID %s. No upstream provenance claim is made.\n", keyID)
	return nil
}

func verify(args []string) error {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	binary := flags.String("binary", "", "local K3s binary copied from the approved mirror")
	lockPath := flags.String("lock", "", "signed customer artifact lock")
	sigPath := flags.String("signature", "", "detached customer signature")
	trustPath := flags.String("trust-bundle", "", "independently provisioned customer artifact public-key bundle")
	expectedDigest := flags.String("expected-digest", "", "digest Terraform is configured to pass to the lab")
	expectedMirror := flags.String("expected-mirror-url", "", "mirror URL Terraform is configured to pass to the lab")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *binary == "" || *lockPath == "" || *sigPath == "" || *trustPath == "" {
		return errors.New("verify requires binary, lock, signature, and independently provisioned trust bundle paths")
	}
	if (*expectedDigest == "") != (*expectedMirror == "") {
		return errors.New("expected-digest and expected-mirror-url must be supplied together")
	}
	lock, err := readPublicFile(*lockPath, 16<<10)
	if err != nil {
		return err
	}
	sig, err := readPublicFile(*sigPath, 4096)
	if err != nil {
		return err
	}
	trust, err := readPublicFile(*trustPath, 16<<10)
	if err != nil {
		return err
	}
	result, err := artifactlock.Verify(lock, sig, trust, *binary, nil)
	if err != nil {
		return err
	}
	if err := checkExpectedInputs(result, *expectedDigest, *expectedMirror); err != nil {
		return err
	}
	fmt.Printf("Verified customer-approved %s %s %s sha256:%s signer=%s mirror=%s\n",
		result.Lock.Artifact, result.Lock.Version, result.Lock.Architecture,
		result.Digest, result.Lock.SignerKeyID, result.Lock.MirrorReference)
	return nil
}

func checkExpectedInputs(result artifactlock.Verified, expectedDigest, expectedMirror string) error {
	if expectedDigest == "" && expectedMirror == "" {
		return nil
	}
	if result.Digest != expectedDigest {
		return errors.New("verified artifact digest does not match the Terraform input")
	}
	if result.Lock.MirrorReference != expectedMirror {
		return errors.New("verified artifact mirror URL does not match the Terraform input")
	}
	return nil
}

func readPrivateSeed(path string) (ed25519.PrivateKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("customer signing key file is unavailable or unsafe")
	}
	defer f.Close()
	info, err := f.Stat()
	linkInfo, linkErr := os.Lstat(path)
	if err != nil || linkErr != nil || !info.Mode().IsRegular() || linkInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, linkInfo) || info.Size() <= 0 || info.Size() > 4096 || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("customer signing key file must be a safe regular file with mode 0600 or stricter")
	}
	data, err := io.ReadAll(io.LimitReader(f, 4097))
	after, statErr := f.Stat()
	if err != nil || statErr != nil || int64(len(data)) != info.Size() || !os.SameFile(info, after) || !after.ModTime().Equal(info.ModTime()) {
		return nil, errors.New("customer signing key file changed while being read")
	}
	text := strings.TrimSuffix(string(data), "\n")
	decoded, err := base64.RawStdEncoding.DecodeString(text)
	if err != nil || base64.RawStdEncoding.EncodeToString(decoded) != text {
		return nil, errors.New("customer signing key file must contain canonical unpadded base64 Ed25519 key material")
	}
	switch len(decoded) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(decoded), nil
	case ed25519.PrivateKeySize:
		private := ed25519.PrivateKey(decoded)
		if !private.Equal(ed25519.NewKeyFromSeed(private.Seed())) {
			return nil, errors.New("invalid customer Ed25519 private key encoding")
		}
		return private, nil
	default:
		return nil, errors.New("invalid customer Ed25519 private key length")
	}
}

func readPublicFile(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("input file is unavailable")
	}
	defer f.Close()
	info, err := f.Stat()
	linkInfo, linkErr := os.Lstat(path)
	if err != nil || linkErr != nil || !info.Mode().IsRegular() || linkInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, linkInfo) || info.Size() <= 0 || info.Size() > max {
		return nil, errors.New("input must be a bounded regular non-symlink file")
	}
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(data)) != info.Size() || int64(len(data)) > max {
		return nil, errors.New("could not read stable input file")
	}
	after, err := f.Stat()
	if err != nil || !os.SameFile(info, after) || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		return nil, errors.New("input changed while being read")
	}
	return data, nil
}

func writePairNew(first string, firstData []byte, second string, secondData []byte) error {
	created := make([]string, 0, 2)
	write := func(path string, data []byte) error {
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if err != nil {
			return errors.New("output files must not already exist")
		}
		created = append(created, path)
		if _, err = file.Write(data); err == nil {
			err = file.Sync()
		}
		if closeErr := file.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return errors.New("could not write output files")
		}
		return nil
	}
	if err := write(first, firstData); err != nil {
		for _, path := range created {
			_ = os.Remove(path)
		}
		return err
	}
	if err := write(second, secondData); err != nil {
		for _, path := range created {
			_ = os.Remove(path)
		}
		return err
	}
	return nil
}

func writeNew(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}
