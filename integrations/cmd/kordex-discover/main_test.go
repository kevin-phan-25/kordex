package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoveryRequiresAnExplicitRootAndArchitecture(t *testing.T) {
	for _, args := range [][2]string{{"", "amd64"}, {"/", ""}, {"/", "guess"}} {
		if err := run(args[0], args[1], false, false); err == nil {
			t.Fatalf("accepted ambiguous discovery context: %v", args)
		}
	}
}
func TestDiscoveryRootCannotEscapeThroughSnapshotSymlinks(t *testing.T) {
	outside := t.TempDir()
	snapshot := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "os-release"), []byte("ID=ubuntu\nVERSION_ID=24.04\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(snapshot, "etc"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "os-release"), filepath.Join(snapshot, "etc/os-release")); err != nil {
		t.Fatal(err)
	}
	if err := run(snapshot, "amd64", false, false); err == nil {
		t.Fatal("discovery followed an out-of-root host identity")
	}
}
