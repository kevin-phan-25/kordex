package lifecycle

import (
	"errors"
	"io/fs"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
)

func TestOSReleaseParsingAndExclusiveFallback(t *testing.T) {
	root := fstest.MapFS{
		"etc/os-release":                 &fstest.MapFile{Data: []byte("ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"24.04\"\nVERSION_CODENAME=noble\nNAME=\"Ubuntu Linux\"\n")},
		"usr/lib/os-release":             &fstest.MapFile{Data: []byte("ID=debian\nVERSION_ID=12\n")},
		"proc/sys/kernel/random/boot_id": &fstest.MapFile{Data: []byte("boot-id\n")},
		"etc/machine-id":                 &fstest.MapFile{Data: []byte("machine-id\n")},
		"usr/bin/apt-get":                &fstest.MapFile{Mode: 0755},
	}
	host, err := DiscoverHost(root, "amd64")
	if err != nil || host.ID != "ubuntu" || host.Version != "24.04" || host.Codename != "noble" || host.PackageManager != "apt" || host.MachineID != "machine-id" || host.BootID != "boot-id" {
		t.Fatalf("discovery=%+v error=%v", host, err)
	}
	if host.Immutable != nil || host.RepositoriesHealthy != nil || host.AvailableBytes != nil || host.RebootRequired != nil {
		t.Fatal("unknown host safety evidence became a positive capability")
	}
	delete(root, "etc/os-release")
	host, err = DiscoverHost(root, "amd64")
	if err != nil || host.ID != "debian" {
		t.Fatalf("fallback: %+v %v", host, err)
	}
	root["etc/os-release"] = &fstest.MapFile{Data: []byte("ID=ubuntu\nID=debian\n")}
	if _, err = DiscoverHost(root, "amd64"); err == nil {
		t.Fatal("malformed preferred file fell back to vendor identity")
	}
}
func TestOSReleaseRejectsAmbiguityWithoutExecutingShell(t *testing.T) {
	for _, data := range []string{"ID=ubuntu\nID=debian", "ID=$(touch /tmp/unsafe)", "ID=\"ubuntu\"\"debian\"", "ID='ubuntu", "ID=ubuntu #inline", "ID=ubuntu\x00", "ID_LIKE=debian", strings.Repeat("X", 65537)} {
		if _, err := ParseOSRelease([]byte(data)); err == nil {
			t.Fatalf("accepted ambiguous os-release %q", data[:min(40, len(data))])
		}
	}
	host, err := ParseOSRelease([]byte("ID=unknown\nID_LIKE=\"rhel fedora\"\nNAME=\"A \\\"quoted\\\" name\"\n"))
	if err != nil || len(host.IDLike) != 2 {
		t.Fatalf("valid quoted metadata: %+v %v", host, err)
	}
}

type deniedFS struct{}

func (deniedFS) Open(string) (fs.File, error) { return nil, fs.ErrPermission }
func TestOSReleasePermissionErrorsDoNotFallBack(t *testing.T) {
	if _, err := DiscoverHost(deniedFS{}, "amd64"); !errors.Is(err, fs.ErrPermission) {
		t.Fatal(err)
	}
}
func TestRegistryNeverUsesIDLikeOrUnknownMutabilityOrExpandsVersions(t *testing.T) {
	r := BuiltinRegistry()
	mutable := false
	host := Host{ID: "ubuntu", Version: "24.04", Architecture: "amd64", PackageManager: "apt", Immutable: &mutable}
	d, err := r.SelectHost(host, PackageUpdate, false)
	if err != nil || d.Name != "apt" {
		t.Fatalf("explicit validation selection: %+v %v", d, err)
	}
	if _, err = r.SelectHost(host, PackageUpdate, true); !errors.Is(err, ErrUnqualified) {
		t.Fatalf("unqualified driver allowed execution: %v", err)
	}
	for _, mutate := range []func(*Host){
		func(h *Host) { h.ID = "unreviewed"; h.IDLike = []string{"ubuntu"} },
		func(h *Host) { h.Version = "26.04" }, func(h *Host) { h.Architecture = "unknown" },
		func(h *Host) { h.Immutable = nil }, func(h *Host) { v := true; h.Immutable = &v },
		func(h *Host) { h.PackageManager = "dnf" },
	} {
		candidate := host
		mutate(&candidate)
		if _, err = r.SelectHost(candidate, PackageUpdate, false); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("incompatible host accepted: %+v %v", candidate, err)
		}
	}
	if _, err = r.SelectHost(host, SecurityUpdate, false); !errors.Is(err, ErrUnsupported) {
		t.Fatal("security-only updates inferred from package support")
	}
}
func TestRegistryOwnershipConcurrentReadsAndAmbiguousDrivers(t *testing.T) {
	d := BuiltinRegistry().Drivers()[0]
	r, err := NewRegistry(d)
	if err != nil {
		t.Fatal(err)
	}
	d.Operations[PackageUpdate] = Unsupported
	d.Compatibility[0].Versions[0] = "changed"
	mutable := false
	host := Host{ID: "ubuntu", Version: "24.04", Architecture: "amd64", PackageManager: "apt", Immutable: &mutable}
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			selected, err := r.SelectHost(host, PackageUpdate, false)
			if err != nil {
				t.Error(err)
				return
			}
			selected.Operations[PackageUpdate] = Unsupported
			selected.Compatibility[0].Versions[0] = "changed"
		})
	}
	wg.Wait()
	copy := r.Drivers()[0]
	copy.Name = "other"
	// Competing image adapters must never be silently selected by priority.
	copy.Kind = ImageDriver
	copy.Operations = map[Operation]Support{ImageUpdate: Unverified}
	original := r.Drivers()[0]
	original.Kind = ImageDriver
	original.Operations = map[Operation]Support{ImageUpdate: Unverified}
	r, err = NewRegistry(original, copy)
	if err != nil {
		t.Fatal(err)
	}
	immutable := true
	host.Immutable = &immutable
	if _, err = r.SelectHost(host, ImageUpdate, false); !errors.Is(err, ErrAmbiguousDriver) {
		t.Fatalf("ambiguous registration selected: %v", err)
	}
	if _, err = NewRegistry(original, original); err == nil {
		t.Fatal("duplicate registration accepted")
	}
	original.Operations[ImageUpdate] = Qualified
	if _, err = NewRegistry(original); err == nil {
		t.Fatal("registration fabricated qualification")
	}
}
func TestKubernetesHintsDoNotTreatCloudVMAsManagedCluster(t *testing.T) {
	for _, tc := range []struct {
		version, provider string
		labels            map[string]string
		want              string
	}{
		{"v1.37.0", "aws:///zone/id", nil, "unknown"},
		{"v1.37.0+k3s1", "", nil, "k3s"},
		{"v1.37.0+rke2r1", "", nil, "rke2"},
		{"v1.37.0+k0s.0", "", nil, "k0s"},
		{"v1.37.0+notk3s1", "", nil, "unknown"},
		{"build-with-rke2-in-name", "", nil, "unknown"},
		{"v1.37.0", "gce://project/zone/node", map[string]string{"cloud.google.com/gke-nodepool": "workers"}, "gke"},
		{"v1.37.0+k3s1", "gce://project/zone/node", map[string]string{"cloud.google.com/gke-nodepool": "workers"}, "unknown"},
	} {
		got := DiscoverKubernetes(tc.version, "containerd://2", ""+tc.provider, tc.labels, false)
		if got.Kubernetes.Distribution != tc.want || got.Validate() != nil {
			t.Fatalf("hint=%+v want=%s", got, tc.want)
		}
	}
}
func TestDriverBindingRequiresExactImmutableIdentities(t *testing.T) {
	b := Binding{Driver: "apt", DriverVersion: "1", ArtifactDigest: strings.Repeat("a", 64), PlanDigest: strings.Repeat("b", 64)}
	if b.Validate() != nil {
		t.Fatal("valid binding rejected")
	}
	b.ArtifactDigest = "latest"
	if b.Validate() == nil {
		t.Fatal("mutable artifact reference accepted")
	}
}
