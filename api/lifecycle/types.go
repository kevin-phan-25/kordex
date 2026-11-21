// Package lifecycle defines discovery and compatibility data. Discovery never
// grants maintenance authorization or establishes production qualification.
package lifecycle

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

type Operation string

const (
	PackageUpdate        Operation = "PackageUpdate"
	SecurityUpdate       Operation = "SecurityUpdate"
	KernelUpdate         Operation = "KernelUpdate"
	Reboot               Operation = "Reboot"
	ImageUpdate          Operation = "ImageUpdate"
	OSReleaseUpdate      Operation = "OSReleaseUpdate"
	KubernetesNodeUpdate Operation = "KubernetesNodeUpdate"
	ControlPlaneUpdate   Operation = "ControlPlaneUpdate"
	NodePoolUpdate       Operation = "NodePoolUpdate"
)

type Support string

const (
	Unsupported Support = "Unsupported"
	Unverified  Support = "Unverified"
	Supported   Support = "Supported"
	Qualified   Support = "Qualified"
)

type DriverKind string

const (
	PackageDriver    DriverKind = "package"
	ImageDriver      DriverKind = "image"
	KubernetesDriver DriverKind = "kubernetes"
)

// Pointer-valued facts distinguish unknown from an observed false/zero value.
type Host struct {
	ID                  string   `json:"id"`
	IDLike              []string `json:"idLike,omitempty"`
	Version             string   `json:"version,omitempty"`
	Codename            string   `json:"codename,omitempty"`
	Variant             string   `json:"variant,omitempty"`
	Architecture        string   `json:"architecture,omitempty"`
	Kernel              string   `json:"kernel,omitempty"`
	PackageManager      string   `json:"packageManager,omitempty"`
	InitSystem          string   `json:"initSystem,omitempty"`
	Immutable           *bool    `json:"immutable,omitempty"`
	Image               string   `json:"image,omitempty"`
	MachineID           string   `json:"machineId,omitempty"`
	BootID              string   `json:"bootId,omitempty"`
	AvailableBytes      *uint64  `json:"availableBytes,omitempty"`
	RepositoriesHealthy *bool    `json:"repositoriesHealthy,omitempty"`
	RebootRequired      *bool    `json:"rebootRequired,omitempty"`
}

type Kubernetes struct {
	Distribution string `json:"distribution"`
	Provider     string `json:"provider"`
	Version      string `json:"version,omitempty"`
	Role         string `json:"role"`
	ControlPlane string `json:"controlPlane"`
	NodePool     string `json:"nodePool,omitempty"`
	Runtime      string `json:"runtime,omitempty"`
}

// Inventory is advisory, versioned and never read as execution permission.
// Kubernetes metadata cannot establish package manager, repository, disk,
// machine identity, or driver compatibility evidence from the host.
type Inventory struct {
	SchemaVersion int        `json:"schemaVersion"`
	Source        string     `json:"source"`
	Kubernetes    Kubernetes `json:"kubernetes"`
}

func (i Inventory) Validate() error {
	k := i.Kubernetes
	if i.SchemaVersion != 1 || i.Source != "kubernetes-node" ||
		!slices.Contains([]string{"unknown", "gke", "eks", "aks", "k3s", "rke2", "k0s", "openshift"}, k.Distribution) ||
		!slices.Contains([]string{"unknown", "gcp", "aws", "azure"}, k.Provider) ||
		!slices.Contains([]string{"worker", "control-plane"}, k.Role) ||
		!slices.Contains([]string{"unknown", "provider-managed"}, k.ControlPlane) ||
		len(k.NodePool) > 253 || len(k.Runtime) > 256 || len(k.Version) > 256 {
		return errors.New("invalid lifecycle inventory")
	}
	for _, value := range []string{k.NodePool, k.Runtime, k.Version} {
		if strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return errors.New("invalid lifecycle inventory control character")
		}
	}
	return nil
}

type Compatibility struct {
	OSID           string   `json:"osId"`
	Versions       []string `json:"versions"`                 // Exact VERSION_ID values, never ID_LIKE.
	MinimumVersion string   `json:"minimumVersion,omitempty"` // Numeric VERSION_ID floor for an explicitly named OS ID.
	Architectures  []string `json:"architectures"`
}
type Descriptor struct {
	Name          string                `json:"name"`
	Version       string                `json:"version"`
	Kind          DriverKind            `json:"kind"`
	Compatibility []Compatibility       `json:"compatibility"`
	Operations    map[Operation]Support `json:"operations"`
	Offline       Support               `json:"offline"`
	Mechanism     string                `json:"mechanism"`
}
type Binding struct {
	Driver         string `json:"driver"`
	DriverVersion  string `json:"driverVersion"`
	ArtifactDigest string `json:"artifactDigest"`
	PlanDigest     string `json:"planDigest"`
}

var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

func (b Binding) Validate() error {
	if b.Driver == "" || b.DriverVersion == "" || !digestPattern.MatchString(b.ArtifactDigest) || !digestPattern.MatchString(b.PlanDigest) {
		return errors.New("driver binding requires exact version, artifact SHA-256 and plan SHA-256")
	}
	return nil
}

var ErrUnsupported = errors.New("lifecycle operation unsupported")
var ErrUnqualified = errors.New("lifecycle operation lacks qualification")
var ErrAmbiguousDriver = errors.New("multiple compatible lifecycle drivers")

// Registry is immutable after construction and safe for concurrent selection.
// It contains compatibility metadata, not privileged commands or credentials.
type Registry struct{ drivers []Descriptor }

func NewRegistry(drivers ...Descriptor) (*Registry, error) {
	r := &Registry{}
	seen := map[string]bool{}
	for _, d := range drivers {
		if d.Name == "" || d.Version == "" || seen[d.Name] ||
			!slices.Contains([]DriverKind{PackageDriver, ImageDriver, KubernetesDriver}, d.Kind) {
			return nil, errors.New("invalid or duplicate driver registration")
		}
		// Qualification comes from retained release evidence, not registration.
		// No built-in or runtime registration can silently claim qualification.
		for _, state := range d.Operations {
			if !slices.Contains([]Support{Unsupported, Unverified, Supported}, state) {
				return nil, errors.New("registration cannot confer operation qualification")
			}
		}
		allowed := map[DriverKind][]Operation{
			PackageDriver:    {PackageUpdate, SecurityUpdate, KernelUpdate, Reboot, OSReleaseUpdate},
			ImageDriver:      {ImageUpdate, Reboot},
			KubernetesDriver: {KubernetesNodeUpdate, ControlPlaneUpdate, NodePoolUpdate},
		}
		for op := range d.Operations {
			if !slices.Contains(allowed[d.Kind], op) {
				return nil, errors.New("operation is incompatible with driver lifecycle model")
			}
		}
		if !slices.Contains([]Support{Unsupported, Unverified, Supported}, d.Offline) {
			return nil, errors.New("invalid offline support")
		}
		seen[d.Name] = true
		r.drivers = append(r.drivers, cloneDescriptor(d))
	}
	return r, nil
}
func cloneDescriptor(d Descriptor) Descriptor {
	d.Compatibility = slices.Clone(d.Compatibility)
	for n := range d.Compatibility {
		d.Compatibility[n].Versions = slices.Clone(d.Compatibility[n].Versions)
		d.Compatibility[n].Architectures = slices.Clone(d.Compatibility[n].Architectures)
	}
	ops := make(map[Operation]Support, len(d.Operations))
	for op, state := range d.Operations {
		ops[op] = state
	}
	d.Operations = ops
	return d
}

func versionAtLeast(observed, minimum string) bool {
	parse := func(value string) ([]int, bool) {
		parts := strings.Split(value, ".")
		if len(parts) == 0 {
			return nil, false
		}
		result := make([]int, len(parts))
		for i, part := range parts {
			if part == "" {
				return nil, false
			}
			for _, r := range part {
				if r < '0' || r > '9' {
					return nil, false
				}
			}
			value, err := strconv.Atoi(part)
			if err != nil {
				return nil, false
			}
			result[i] = value
		}
		return result, true
	}
	left, okLeft := parse(observed)
	right, okRight := parse(minimum)
	if !okLeft || !okRight {
		return false
	}
	length := max(len(left), len(right))
	for i := 0; i < length; i++ {
		l, r := 0, 0
		if i < len(left) {
			l = left[i]
		}
		if i < len(right) {
			r = right[i]
		}
		if l != r {
			return l > r
		}
	}
	return true
}
func (r *Registry) Drivers() []Descriptor {
	result := make([]Descriptor, len(r.drivers))
	for i, d := range r.drivers {
		result[i] = cloneDescriptor(d)
	}
	return result
}
func (r *Registry) SelectHost(host Host, op Operation, execute bool) (Descriptor, error) {
	var candidates []Descriptor
	for _, d := range r.drivers {
		if d.Kind == KubernetesDriver || d.Operations[op] == "" || d.Operations[op] == Unsupported {
			continue
		}
		if host.Immutable == nil || *host.Immutable != (d.Kind == ImageDriver) {
			continue
		}
		if d.Kind == PackageDriver && host.PackageManager != d.Name {
			continue
		}
		for _, match := range d.Compatibility {
			versionMatches := slices.Contains(match.Versions, host.Version) ||
				(match.MinimumVersion != "" && versionAtLeast(host.Version, match.MinimumVersion))
			if host.ID == match.OSID && versionMatches && slices.Contains(match.Architectures, host.Architecture) {
				candidates = append(candidates, d)
				break
			}
		}
	}
	if len(candidates) == 0 {
		return Descriptor{}, fmt.Errorf("%w: no explicit OS/version/architecture match", ErrUnsupported)
	}
	if len(candidates) != 1 {
		return Descriptor{}, ErrAmbiguousDriver
	}
	d := candidates[0]
	if execute {
		return Descriptor{}, fmt.Errorf("%w: %s %s", ErrUnqualified, d.Name, op)
	}
	return cloneDescriptor(d), nil
}
