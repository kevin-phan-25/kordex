package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"kordex.local/agent/internal/client"
	"kordex.local/agent/internal/connectivitycheck"
	"kordex.local/agent/internal/state"
)

func runConnectivityCheck(args []string) int {
	flags := flag.NewFlagSet("connectivity-check", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	var cidrs stringList
	flags.Var(&cidrs, "allowed-cidr", "approved private destination CIDR (repeatable)")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return 2
	}
	result := connectivitycheck.Result{Route: "GET /v1/agent/identity", CertificateMapping: "not_verified", APIResponse: "not_reached", Status: "configuration_invalid"}
	if os.Getenv("KORDEX_MTLS_ENABLED") != "true" {
		return writeConnectivityResult(result)
	}
	mtls, err := client.LoadMTLSConfig(os.Getenv("KORDEX_MTLS_CLIENT_CERT_FILE"), os.Getenv("KORDEX_MTLS_CLIENT_KEY_FILE"), os.Getenv("KORDEX_MTLS_SERVER_CA_FILE"), os.Getenv("KORDEX_MTLS_SERVER_NAME"))
	if err != nil {
		return writeConnectivityResult(result)
	}
	statePath := os.Getenv("KORDEX_STATE_SECRET_FILE")
	if statePath == "" {
		return writeConnectivityResult(result)
	}
	identity, err := (state.ProjectedSecretStore{Path: statePath}).Load(context.Background())
	if err != nil {
		result.Status = "agent_identity_unavailable"
		return writeConnectivityResult(result)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	gatewayAuthSetting := os.Getenv("KORDEX_GATEWAY_AUTH_REQUIRED")
	result = connectivitycheck.Check(ctx, connectivitycheck.Config{
		Endpoint: os.Getenv("KORDEX_CONTROL_PLANE_URL"), ClusterID: os.Getenv("KORDEX_CLUSTER_ID"),
		Identity: identity, MTLS: mtls, AllowedCIDRs: cidrs, Timeout: 18 * time.Second,
		GatewayAccessHeadersConfigured: os.Getenv("KORDEX_GATEWAY_CLIENT_ID") != "" || os.Getenv("KORDEX_GATEWAY_CLIENT_SECRET") != "" || (gatewayAuthSetting != "" && gatewayAuthSetting != "false"),
	}, connectivitycheck.Dependencies{})
	return writeConnectivityResult(result)
}

func writeConnectivityResult(result connectivitycheck.Result) int {
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, "connectivity check report could not be written")
		return 2
	}
	if result.Status != "verified" {
		return 1
	}
	return 0
}

type stringList []string

func (s *stringList) String() string { return "approved private CIDR list" }
func (s *stringList) Set(value string) error {
	*s = append(*s, value)
	return nil
}
