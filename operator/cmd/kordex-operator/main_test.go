package main

import "testing"

func TestProviderAndHostUpgradeExecutorsAreOptionalByDefault(t *testing.T) {
	t.Setenv("KORDEX_ENABLE_GKE_UPGRADES", "")
	t.Setenv("KORDEX_ENABLE_HOST_UPGRADES", "")

	gkeExecutor, err := configuredGKENodePoolExecutor()
	if err != nil {
		t.Fatalf("operator startup unexpectedly requires GKE configuration: %v", err)
	}
	if gkeExecutor != nil {
		t.Fatal("GKE executor was enabled without explicit opt-in")
	}

	hostExecutor, err := configuredUpgradeExecutor(nil, "")
	if err != nil {
		t.Fatalf("operator startup unexpectedly requires host-upgrade configuration: %v", err)
	}
	if hostExecutor != nil {
		t.Fatal("host executor was enabled without explicit opt-in")
	}
}

func TestFalseUpgradeFlagsKeepExecutorsDisabled(t *testing.T) {
	t.Setenv("KORDEX_ENABLE_GKE_UPGRADES", "false")
	t.Setenv("KORDEX_ENABLE_HOST_UPGRADES", "false")

	gkeExecutor, err := configuredGKENodePoolExecutor()
	if err != nil || gkeExecutor != nil {
		t.Fatalf("explicitly disabled GKE executor returned executor=%v err=%v", gkeExecutor, err)
	}
	hostExecutor, err := configuredUpgradeExecutor(nil, "")
	if err != nil || hostExecutor != nil {
		t.Fatalf("explicitly disabled host executor returned executor=%v err=%v", hostExecutor, err)
	}
}

func TestInvalidGKEUpgradeFlagFailsClosed(t *testing.T) {
	t.Setenv("KORDEX_ENABLE_GKE_UPGRADES", "yes")
	if executor, err := configuredGKENodePoolExecutor(); err == nil || executor != nil {
		t.Fatalf("invalid GKE upgrade setting was accepted: executor=%v err=%v", executor, err)
	}
}
