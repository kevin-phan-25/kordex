package main

import "testing"

func TestMTLSModeIsExplicitAndCannotSilentlyDowngrade(t *testing.T) {
	for _, enabled := range []string{"", "false"} {
		got, err := configuredMTLSEnabled(enabled, "", "", "", "", "")
		if err != nil || got {
			t.Fatalf("configuredMTLSEnabled(%q) = %v, %v; want disabled legacy mode", enabled, got, err)
		}
	}
	if got, err := configuredMTLSEnabled("true", "/cert", "/key", "/ca", "relay.example.internal", ""); err != nil || !got {
		t.Fatalf("complete enabled config = %v, %v", got, err)
	}
	for _, tc := range []struct{ enabled, cert, key, ca, name string }{
		{enabled: "true"},
		{enabled: "false", cert: "/cert"},
		{enabled: "", ca: "/ca"},
		{enabled: "yes"},
	} {
		if _, err := configuredMTLSEnabled(tc.enabled, tc.cert, tc.key, tc.ca, tc.name, ""); err == nil {
			t.Fatalf("accepted incomplete or contradictory mTLS mode: %+v", tc)
		}
	}
	if _, err := configuredMTLSEnabled("true", "/cert", "/key", "/server-ca", "relay.example.internal", "/legacy-ca"); err == nil {
		t.Fatal("accepted ambiguous legacy CA configuration in mTLS mode")
	}
}
