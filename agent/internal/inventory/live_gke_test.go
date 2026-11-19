package inventory

import (
	"context"
	"os"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/tools/clientcmd"
)

// Opt-in live test. It only lists Kubernetes metadata and never mutates the cluster.
func TestLiveGKEInventory(t *testing.T) {
	if os.Getenv("KORDEX_LIVE_GKE_INVENTORY") != "1" {
		t.Skip("set KORDEX_LIVE_GKE_INVENTORY=1 to run read-only against the active kube context")
	}
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig := os.Getenv("KUBECONFIG"); kubeconfig != "" {
		loadingRules.ExplicitPath = kubeconfig
	}
	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		t.Fatal("Kubernetes client configuration unavailable")
	}
	config.Timeout = 20 * time.Second
	kube, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatal("Kubernetes client creation failed")
	}
	meta, err := metadata.NewForConfig(config)
	if err != nil {
		t.Fatal("Kubernetes metadata client creation failed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	report, err := (Collector{Client: kube, Metadata: meta}).Collect(ctx)
	if err != nil {
		t.Fatalf("read-only live collection failed: %v", err)
	}
	if report.ClusterUID == "" || len(report.Nodes) != 3 {
		t.Fatalf("expected a cluster identity and three nodes, got %d nodes", len(report.Nodes))
	}
	cos, ubuntu := 0, 0
	for _, node := range report.Nodes {
		if !node.Ready {
			t.Errorf("node %s was not Ready", node.Name)
		}
		switch node.OSID {
		case "cos":
			cos++
		case "ubuntu":
			if node.OSVersion != "24.04.5" {
				t.Errorf("Ubuntu node version was %q", node.OSVersion)
			}
			ubuntu++
		default:
			t.Errorf("unrecognized expected GKE OS classification %q for node %s", node.OSID, node.Name)
		}
		t.Logf("node=%s os=%s version=%s ready=%t", node.Name, node.OSID, node.OSVersion, node.Ready)
	}
	if cos != 2 || ubuntu != 1 {
		t.Fatalf("expected 2 COS and 1 Ubuntu node, got cos=%d ubuntu=%d", cos, ubuntu)
	}
	t.Logf("cluster kubernetesVersion=%s nodeCount=%d", report.KubernetesVersion, len(report.Nodes))
}
