package lifecycle

// BuiltinRegistry describes existing execution catalogs and explicitly blocked
// extension targets. Registering a descriptor never enables execution. New
// package/image/provider adapters need their own implementation and evidence.
func BuiltinRegistry() *Registry {
	arches := []string{"amd64", "arm64"}
	match := func(id string, versions ...string) Compatibility {
		return Compatibility{OSID: id, Versions: versions, Architectures: arches}
	}
	ops := func(state Support) map[Operation]Support {
		return map[Operation]Support{PackageUpdate: state, KernelUpdate: state, Reboot: state, SecurityUpdate: Unsupported, OSReleaseUpdate: Unsupported}
	}
	drivers := []Descriptor{
		{Name: "apt", Version: "1", Kind: PackageDriver, Compatibility: []Compatibility{match("ubuntu", "24.04"), match("debian", "12")}, Operations: ops(Unverified), Offline: Unverified, Mechanism: "kordex.os-upgrade.debian.v2"},
		{Name: "dnf", Version: "1", Kind: PackageDriver, Compatibility: []Compatibility{match("rhel", "9.5"), match("rocky", "9.5"), match("almalinux", "9.5"), match("amzn", "2023")}, Operations: ops(Unverified), Offline: Unverified, Mechanism: "kordex.os-upgrade.rhel.v1"},
	}
	for _, target := range []struct {
		name string
		ids  []string
	}{{"yum", []string{"amzn", "rhel"}}, {"zypper", []string{"sles", "opensuse-leap", "opensuse-tumbleweed"}}, {"apk", []string{"alpine"}}, {"pacman", []string{"arch", "manjaro"}}, {"portage", []string{"gentoo"}}, {"xbps", []string{"void"}}} {
		d := Descriptor{Name: target.name, Version: "1", Kind: PackageDriver, Operations: ops(Unsupported), Offline: Unsupported, Mechanism: "not implemented"}
		for _, id := range target.ids {
			d.Compatibility = append(d.Compatibility, match(id))
		}
		drivers = append(drivers, d)
	}
	for _, target := range []struct {
		name string
		ids  []string
	}{{"bootc", []string{"fedora", "rhel"}}, {"rpm-ostree", []string{"fedora", "rhel"}}, {"flatcar", []string{"flatcar"}}, {"talos", []string{"talos"}}, {"kairos", []string{"kairos"}}} {
		d := Descriptor{Name: target.name, Version: "1", Kind: ImageDriver, Operations: map[Operation]Support{ImageUpdate: Unsupported, Reboot: Unsupported}, Offline: Unsupported, Mechanism: "vendor adapter required; no generic SSH fallback"}
		for _, id := range target.ids {
			d.Compatibility = append(d.Compatibility, match(id))
		}
		drivers = append(drivers, d)
	}
	for _, name := range []string{"kubeadm", "k3s", "rke2", "eks", "aks", "gke", "openshift", "microk8s", "k0s"} {
		state := Unsupported
		if name == "gke" {
			state = Unverified
		}
		drivers = append(drivers, Descriptor{Name: name, Version: "1", Kind: KubernetesDriver, Operations: map[Operation]Support{NodePoolUpdate: state, KubernetesNodeUpdate: Unsupported, ControlPlaneUpdate: Unsupported}, Offline: Unsupported, Mechanism: "distribution/provider-native adapter; generic package control-plane updates prohibited"})
	}
	r, err := NewRegistry(drivers...)
	if err != nil {
		panic(err)
	}
	return r
}
