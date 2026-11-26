package auditchain

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// LoadPrivateKeyFile accepts the base64 Ed25519 seed format written by
// kordex-keygen and refuses symlinks and files readable by group or other.
func LoadPrivateKeyFile(path string) (ed25519.PrivateKey, error) {
	return loadPrivateKeyFile(path, false)
}

// LoadMountedPrivateKeyFile accepts a read-only Kubernetes projected Secret
// mode (0440) for a pod whose fsGroup is dedicated to that API workload. It
// resolves kubelet's key and ..data symlinks only within the mounted directory,
// then opens the resolved regular file without following a final symlink.
func LoadMountedPrivateKeyFile(path string) (ed25519.PrivateKey, error) {
	resolved, err := resolveProjectedSecretPath(path)
	if err != nil {
		return nil, errors.New("audit signing key must be a regular file within its projected Secret mount")
	}
	return loadPrivateKeyFile(resolved, true)
}

const maxProjectedSecretSymlinks = 8

// resolveProjectedSecretPath handles the layout produced by a Kubernetes
// Secret volume (key -> ..data/key, ..data -> ..<timestamp>) without allowing
// a symlink to escape the dedicated mount root. The mount is read-only in the
// workload; the final open and inode comparison still detect replacement of
// the resolved key file between validation and use.
func resolveProjectedSecretPath(path string) (string, error) {
	if path == "" {
		return "", errors.New("empty projected Secret key path")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	root := filepath.Clean(filepath.Dir(absolute))
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("projected Secret mount root must be a real directory")
	}
	current := filepath.Clean(absolute)
	links := 0
	for {
		relative, err := filepath.Rel(root, current)
		if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
			return "", errors.New("projected Secret path escapes its mount root")
		}
		components := strings.Split(relative, string(filepath.Separator))
		walk := root
		restarted := false
		for index, component := range components {
			walk = filepath.Join(walk, component)
			info, err := os.Lstat(walk)
			if err != nil {
				return "", err
			}
			if info.Mode()&os.ModeSymlink != 0 {
				links++
				if links > maxProjectedSecretSymlinks {
					return "", errors.New("projected Secret has too many symlinks")
				}
				target, err := os.Readlink(walk)
				if err != nil || filepath.IsAbs(target) {
					return "", errors.New("projected Secret symlink target must be relative")
				}
				target = filepath.Clean(filepath.Join(filepath.Dir(walk), target))
				targetRelative, err := filepath.Rel(root, target)
				if err != nil || targetRelative == ".." || strings.HasPrefix(targetRelative, ".."+string(filepath.Separator)) || filepath.IsAbs(targetRelative) {
					return "", errors.New("projected Secret symlink escapes its mount root")
				}
				remaining := components[index+1:]
				current = filepath.Join(append([]string{target}, remaining...)...)
				restarted = true
				break
			}
			if index < len(components)-1 && !info.IsDir() {
				return "", errors.New("projected Secret path has a non-directory parent")
			}
			if index == len(components)-1 && !info.Mode().IsRegular() {
				return "", errors.New("projected Secret key is not a regular file")
			}
		}
		if !restarted {
			return current, nil
		}
	}
}

func loadPrivateKeyFile(path string, allowGroupRead bool) (ed25519.PrivateKey, error) {
	if path == "" {
		return nil, errors.New("audit signing key file is required")
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, errors.New("audit signing key file must be a private regular file with mode 0600 or stricter")
	}
	perms := before.Mode().Perm()
	allowedMode := perms == 0o0400 || perms == 0o0600
	if allowGroupRead && perms == 0o0440 {
		allowedMode = true
	}
	if !before.Mode().IsRegular() || !allowedMode || before.Size() < 40 || before.Size() > 128 {
		return nil, errors.New("audit signing key file must be a private regular file with mode 0600 or stricter")
	}
	flags := os.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC | syscall.O_NONBLOCK
	fd, err := syscall.Open(path, flags, 0)
	if err != nil {
		return nil, errors.New("open audit signing key failed")
	}
	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("open audit signing key failed")
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) {
		return nil, errors.New("audit signing key changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(f, 129))
	if err != nil || len(data) > 128 {
		return nil, errors.New("read audit signing key failed")
	}
	raw, err := base64.RawStdEncoding.DecodeString(string(bytes.TrimSpace(data)))
	if err != nil {
		return nil, errors.New("audit signing key encoding is invalid")
	}
	if len(raw) == ed25519.SeedSize {
		return ed25519.NewKeyFromSeed(raw), nil
	}
	if len(raw) == ed25519.PrivateKeySize && bytes.Equal(ed25519.NewKeyFromSeed(raw[:ed25519.SeedSize]), raw) {
		return ed25519.PrivateKey(raw), nil
	}
	return nil, errors.New("audit signing key must contain an Ed25519 seed or canonical private key")
}
