package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func TestMaintenanceAuthorizationBinding(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	p := MaintenancePermit{OrganizationID: "33333333-3333-4333-8333-333333333333", ClusterID: "11111111-1111-4111-8111-111111111111", ClusterUID: "kube-system-uid", MaintenanceRequest: MaintenanceRequest{OperationID: "22222222-2222-4222-8222-222222222222", NodeName: "worker1", NodeUID: "worker-uid", Action: DrainAndVerify, Policy: PolicyReference{Name: "safe", UID: "policy-uid", Generation: 1}}, IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(time.Minute)}
	command, err := SignMaintenance(p, key)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]ed25519.PublicKey{KeyID(pub): pub}
	parsed, err := DecodeMaintenance(command, keys)
	if err != nil || !parsed.Fresh(now) {
		t.Fatal(err)
	}
	tampered := command
	tampered.Authorization = strings.ReplaceAll(command.Authorization, "worker1", "worker2")
	if _, err = DecodeMaintenance(tampered, keys); err == nil {
		t.Fatal("node substitution accepted")
	}
	if parsed.Fresh(now.Add(2 * time.Minute)) {
		t.Fatal("expired authorization accepted")
	}
	p.Action = "Reboot"
	unsupported, err := SignMaintenance(p, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeMaintenance(unsupported, keys); err == nil {
		t.Fatal("unsupported destructive action accepted")
	}
	p.Action = ValidateOnly
	p.ExpiresAt = now.Add(time.Hour)
	unbounded, _ := SignMaintenance(p, key)
	if _, err = DecodeMaintenance(unbounded, keys); err == nil {
		t.Fatal("unbounded permit accepted")
	}
}
