package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	operations "kordex.local/api/operations/v1alpha1"
	"kordex.local/api/protocol"
	"kordex.local/operator/internal/controller"
	"kordex.local/operator/internal/execution"
	"kordex.local/operator/internal/provider/gke"
	"kordex.local/operator/internal/safety"
)

type apiHealth struct{ Client rest.Interface }

func (a apiHealth) Ready(ctx context.Context) error {
	_, err := a.Client.Get().AbsPath("/readyz").DoRaw(ctx)
	return err
}
func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("operator stopped", "error", err.Error())
		os.Exit(1)
	}
}

func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func run(logger *slog.Logger) error {
	ctrl.SetLogger(zap.New(zap.UseDevMode(false)))
	cluster := os.Getenv("KORDEX_CLUSTER_ID")
	namespace := os.Getenv("KORDEX_NAMESPACE")
	if !protocol.ValidUUID(cluster) || namespace == "" {
		return fmt.Errorf("valid KORDEX_CLUSTER_ID and KORDEX_NAMESPACE required")
	}
	data, err := os.ReadFile(os.Getenv("KORDEX_HUB_PUBLIC_KEYS_FILE"))
	if err != nil {
		return fmt.Errorf("read hub trust bundle: %w", err)
	}
	var encoded map[string]string
	if err = json.Unmarshal(data, &encoded); err != nil || len(encoded) == 0 {
		return fmt.Errorf("invalid hub trust bundle")
	}
	keys := map[string]ed25519.PublicKey{}
	for id, value := range encoded {
		key, err := protocol.DecodeKey(value)
		if err != nil || protocol.KeyID(key) != id {
			return fmt.Errorf("hub key ID mismatch")
		}
		keys[id] = key
	}
	cfg, err := ctrl.GetConfig()
	if err != nil {
		return err
	}
	cfg.Timeout = 15 * time.Second
	cfg.QPS = 20
	cfg.Burst = 30
	kube, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return err
	}
	dynamicClient, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return err
	}
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		LeaderElection:          true,
		LeaderElectionID:        "kordex-operator",
		LeaderElectionNamespace: namespace,
		Cache:                   cache.Options{DefaultNamespaces: map[string]cache.Config{namespace: {}}},
		Metrics:                 metricsserver.Options{BindAddress: envOrDefault("KORDEX_METRICS_ADDR", "127.0.0.1:8082")},
		HealthProbeBindAddress:  ":8081",
	})
	if err != nil {
		return err
	}
	if err = clientgoscheme.AddToScheme(mgr.GetScheme()); err != nil {
		return err
	}
	if err = operations.AddToScheme(mgr.GetScheme()); err != nil {
		return err
	}
	upgrader, err := configuredUpgradeExecutor(kube, namespace)
	if err != nil {
		return err
	}
	gkeUpgrader, err := configuredGKENodePoolExecutor()
	if err != nil {
		return err
	}
	quorum, closeQuorum, err := safety.NewEtcdQuorumFromEnv()
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := closeQuorum(); closeErr != nil {
			logger.Error("close etcd quorum client", "error", closeErr.Error())
		}
	}()
	checker := &safety.Checker{Reader: mgr.GetAPIReader(), Storage: safety.RookCephStorage{Reader: mgr.GetAPIReader(), Dynamic: dynamicClient, Metrics: safety.RookServiceMetrics{Reader: mgr.GetAPIReader()}}, Quorum: quorum, API: apiHealth{Client: kube.Discovery().RESTClient()}}
	reconciler := &controller.Reconciler{Client: mgr.GetClient(), Reader: mgr.GetAPIReader(), Checker: checker, Evictor: execution.KubernetesEvictor{Client: kube}, Upgrader: upgrader, GKE: gkeUpgrader, Keys: keys, ClusterID: cluster, Logger: logger}
	if err = reconciler.SetupWithManager(mgr); err != nil {
		return err
	}
	if err = (&controller.PolicyReconciler{Client: mgr.GetClient()}).SetupWithManager(mgr); err != nil {
		return err
	}
	if err = (&controller.CampaignReconciler{Client: mgr.GetClient()}).SetupWithManager(mgr); err != nil {
		return err
	}
	if err = mgr.Add(&controller.CapabilityPublisher{
		Leases: kube.CoordinationV1().Leases(namespace), HostUpgrades: upgrader != nil,
		GKENodePoolUpgrade: gkeUpgrader != nil, Logger: logger,
	}); err != nil {
		return err
	}
	if err = mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return err
	}
	if err = mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return err
	}
	return mgr.Start(ctrl.SetupSignalHandler())
}

func configuredGKENodePoolExecutor() (*gke.Client, error) {
	switch os.Getenv("KORDEX_ENABLE_GKE_UPGRADES") {
	case "", "false":
		return nil, nil
	case "true":
		return gke.NewClient(), nil
	default:
		return nil, fmt.Errorf("KORDEX_ENABLE_GKE_UPGRADES must be true or false")
	}
}

func configuredUpgradeExecutor(kube kubernetes.Interface, namespace string) (*execution.AnsibleJobExecutor, error) {
	switch os.Getenv("KORDEX_ENABLE_HOST_UPGRADES") {
	case "", "false":
		return nil, nil
	case "true":
	default:
		return nil, fmt.Errorf("KORDEX_ENABLE_HOST_UPGRADES must be true or false")
	}
	executor := &execution.AnsibleJobExecutor{
		Client:                       kube,
		Namespace:                    namespace,
		LedgerNamespace:              protocol.SlotNamespace,
		ServiceAccount:               "kordex-upgrade-runner",
		SSHUser:                      os.Getenv("KORDEX_UPGRADE_SSH_USER"),
		SSHCredentialSecret:          os.Getenv("KORDEX_UPGRADE_SSH_SECRET"),
		KnownHostsConfigMap:          os.Getenv("KORDEX_UPGRADE_KNOWN_HOSTS"),
		AllowedExecutionEnvironments: configuredCSV(os.Getenv("KORDEX_UPGRADE_EE_ALLOWLIST")),
		ImagePullSecrets:             configuredCSV(os.Getenv("KORDEX_UPGRADE_IMAGE_PULL_SECRETS")),
	}
	if err := executor.Validate(); err != nil {
		return nil, fmt.Errorf("validate optional host upgrade executor configuration: %w", err)
	}
	return executor, nil
}

func configuredCSV(raw string) []string {
	values := strings.Split(raw, ",")
	allowed := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			allowed = append(allowed, value)
		}
	}
	return allowed
}
