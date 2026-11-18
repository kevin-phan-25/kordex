package lifecycle

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

var osKey = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
var osID = regexp.MustCompile(`^[a-z0-9._-]+$`)

// ParseOSRelease parses data; it never sources a shell or expands variables.
// Ambiguous/duplicate assignments and malformed quoting are rejected.
func ParseOSRelease(data []byte) (Host, error) {
	var host Host
	if len(data) > 65536 || !utf8.Valid(data) {
		return host, errors.New("invalid or oversized os-release")
	}
	values := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || !osKey.MatchString(key) {
			return host, errors.New("invalid os-release assignment")
		}
		if _, duplicate := values[key]; duplicate {
			return host, fmt.Errorf("duplicate os-release key: %s", key)
		}
		decoded, err := releaseValue(value)
		if err != nil {
			return host, err
		}
		values[key] = decoded
	}
	if err := scanner.Err(); err != nil {
		return host, err
	}
	if !osID.MatchString(values["ID"]) {
		return host, errors.New("os-release requires an explicit valid ID")
	}
	host = Host{ID: values["ID"], Version: values["VERSION_ID"], Codename: values["VERSION_CODENAME"], Variant: values["VARIANT_ID"], Image: values["IMAGE_ID"]}
	for _, id := range strings.Fields(values["ID_LIKE"]) {
		if !osID.MatchString(id) {
			return Host{}, errors.New("invalid ID_LIKE")
		}
		host.IDLike = append(host.IDLike, id)
	}
	return host, nil
}
func releaseValue(value string) (string, error) {
	if strings.ContainsAny(value, "\x00\r\n") {
		return "", errors.New("invalid os-release control character")
	}
	if value == "" {
		return "", nil
	}
	quote := byte(0)
	if value[0] == '\'' || value[0] == '"' {
		quote = value[0]
		if len(value) < 2 || value[len(value)-1] != quote {
			return "", errors.New("unterminated os-release quote")
		}
		value = value[1 : len(value)-1]
	}
	var result strings.Builder
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if quote == '\'' {
			if ch == '\'' {
				return "", errors.New("concatenated os-release quotes")
			}
			result.WriteByte(ch)
			continue
		}
		if ch == '\\' {
			if i+1 >= len(value) {
				return "", errors.New("invalid os-release escape")
			}
			next := value[i+1]
			if quote == '"' && !strings.ContainsRune("\"\\$`", rune(next)) {
				result.WriteByte(ch)
				continue
			}
			i++
			result.WriteByte(next)
			continue
		}
		if ch == '$' || ch == '`' || ch == '"' || ch == '\'' || quote == 0 && !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-", rune(ch)) {
			return "", errors.New("unsupported os-release quoting or expansion")
		}
		result.WriteByte(ch)
	}
	decoded := result.String()
	if strings.IndexFunc(decoded, unicode.IsControl) >= 0 {
		return "", errors.New("invalid os-release control character")
	}
	return decoded, nil
}

func readBounded(root fs.FS, path string) ([]byte, error) {
	file, err := root.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil {
		return nil, err
	}
	if len(data) > 65536 {
		return nil, errors.New("host discovery file exceeds bound")
	}
	return data, nil
}

// DiscoverHost reads only the explicitly supplied host root/snapshot. A pod's
// own root must never be presented as evidence about a remote Kubernetes node.
// Repository health, disk availability and reboot need remain unknown until a
// driver-specific, read-only probe supplies authoritative evidence.
func DiscoverHost(root fs.FS, architecture string) (Host, error) {
	data, err := readBounded(root, "etc/os-release")
	if errors.Is(err, fs.ErrNotExist) {
		data, err = readBounded(root, "usr/lib/os-release")
	}
	if err != nil {
		return Host{}, err
	}
	host, err := ParseOSRelease(data)
	if err != nil {
		return Host{}, err
	}
	host.Architecture = architecture
	for path, field := range map[string]*string{"proc/sys/kernel/osrelease": &host.Kernel, "proc/sys/kernel/random/boot_id": &host.BootID, "etc/machine-id": &host.MachineID, "proc/1/comm": &host.InitSystem} {
		data, err = readBounded(root, path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return Host{}, err
		}
		*field = strings.TrimSpace(string(data))
	}
	for _, manager := range []struct{ name, path string }{{"apt", "usr/bin/apt-get"}, {"dnf", "usr/bin/dnf"}, {"yum", "usr/bin/yum"}, {"zypper", "usr/bin/zypper"}, {"apk", "sbin/apk"}, {"pacman", "usr/bin/pacman"}} {
		entry, err := fs.Stat(root, manager.path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return Host{}, err
		}
		if entry.Mode().IsRegular() && entry.Mode().Perm()&0111 != 0 {
			if host.PackageManager != "" && !(host.PackageManager == "dnf" && manager.name == "yum") {
				host.PackageManager = "ambiguous"
				break
			}
			host.PackageManager = manager.name
		}
	}
	// These are positive immutable identifiers, never inferred from ID_LIKE.
	if host.Variant == "coreos" || host.Variant == "edge" || host.Image != "" || host.ID == "flatcar" || host.ID == "talos" || host.ID == "kairos" {
		immutable := true
		host.Immutable = &immutable
	}
	return host, nil
}

// DiscoverKubernetes uses only node metadata as an advisory distribution hint.
// Cloud VM identity alone does not establish EKS/GKE/AKS cluster ownership.
func DiscoverKubernetes(version, runtime, providerID string, labels map[string]string, controlPlane bool) Inventory {
	k := Kubernetes{Distribution: "unknown", Provider: "unknown", Version: version, Runtime: runtime, Role: "worker", ControlPlane: "unknown"}
	if controlPlane {
		k.Role = "control-plane"
	}
	for prefix, provider := range map[string]string{"gce://": "gcp", "aws://": "aws", "azure://": "azure"} {
		if strings.HasPrefix(providerID, prefix) {
			k.Provider = provider
		}
	}
	type hint struct {
		distribution, pool string
		managed            bool
	}
	var hints []hint
	for _, marker := range []string{"k3s", "rke2", "k0s"} {
		if strings.Contains(strings.ToLower(version), marker) {
			hints = append(hints, hint{distribution: marker})
		}
	}
	for _, provider := range []struct{ name, cloud, label string }{{"gke", "gcp", "cloud.google.com/gke-nodepool"}, {"eks", "aws", "eks.amazonaws.com/nodegroup"}, {"aks", "azure", "kubernetes.azure.com/agentpool"}} {
		if pool := labels[provider.label]; pool != "" && k.Provider == provider.cloud {
			hints = append(hints, hint{provider.name, pool, true})
		}
	}
	if labels["machineconfiguration.openshift.io/currentConfig"] != "" {
		hints = append(hints, hint{distribution: "openshift"})
	}
	if len(hints) == 1 {
		k.Distribution = hints[0].distribution
		k.NodePool = hints[0].pool
		if hints[0].managed {
			k.ControlPlane = "provider-managed"
		}
	}
	return Inventory{SchemaVersion: 1, Source: "kubernetes-node", Kubernetes: k}
}
