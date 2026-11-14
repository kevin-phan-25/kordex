package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"

	"kordex.local/agent/internal/client"
	"kordex.local/agent/internal/inventory"
	"kordex.local/agent/internal/runner"
	"kordex.local/agent/internal/state"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("agent stopped", "error", err.Error())
		os.Exit(1)
	}
}
func run(logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var cfg *rest.Config
	var err error
	if path := os.Getenv("KUBECONFIG"); path != "" {
		cfg, err = clientcmd.BuildConfigFromFlags("", path)
	} else {
		cfg, err = rest.InClusterConfig()
	}
	if err != nil {
		return fmt.Errorf("Kubernetes client configuration unavailable")
	}
	cfg.Timeout = 20 * time.Second
	cfg.QPS = 5
	cfg.Burst = 10
	kube, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("Kubernetes client creation failed")
	}
	var ca []byte
	if file := os.Getenv("KORDEX_CA_FILE"); file != "" {
		ca, err = os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("read management CA bundle: %w", err)
		}
	}
	remote, err := client.New(os.Getenv("KORDEX_CONTROL_PLANE_URL"), os.Getenv("KORDEX_CLUSTER_ID"), os.Getenv("KORDEX_LOCAL_DEVELOPMENT") == "true", ca)
	if err != nil {
		return err
	}
	enrollment := ""
	if file := os.Getenv("KORDEX_ENROLLMENT_TOKEN_FILE"); file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("read enrollment token file: %w", err)
		}
		enrollment = strings.TrimSpace(string(b))
	}
	namespace := os.Getenv("KORDEX_NAMESPACE")
	if namespace == "" {
		namespace = "kordex-system"
	}
	var durable state.Store
	if file := os.Getenv("KORDEX_STATE_FILE"); file != "" {
		durable = state.FileStore{Path: file}
	} else {
		name := os.Getenv("KORDEX_STATE_SECRET")
		if name == "" {
			return fmt.Errorf("KORDEX_STATE_SECRET required")
		}
		durable = state.KubernetesStore{Client: kube, Namespace: namespace, Name: name}
	}
	worker := &runner.Runner{Client: remote, Store: durable, Collector: inventory.Collector{Client: kube}, EnrollmentToken: enrollment, Logger: logger}
	if os.Getenv("KORDEX_LOCAL_DEVELOPMENT") == "true" && os.Getenv("KORDEX_STATE_FILE") != "" {
		err := worker.Run(ctx)
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	}
	lease := os.Getenv("KORDEX_LEASE_NAME")
	identity := os.Getenv("POD_UID")
	if lease == "" || identity == "" {
		return fmt.Errorf("KORDEX_LEASE_NAME and POD_UID required")
	}
	lock := &resourcelock.LeaseLock{LeaseMeta: metav1.ObjectMeta{Name: lease, Namespace: namespace}, Client: kube.CoordinationV1(), LockConfig: resourcelock.ResourceLockConfig{Identity: identity}}
	workerDone := make(chan struct{})
	workerStarted := make(chan struct{})
	election, err := leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{Lock: lock, LeaseDuration: 30 * time.Second, RenewDeadline: 20 * time.Second, RetryPeriod: 5 * time.Second, ReleaseOnCancel: false, Name: "kordex-agent", Callbacks: leaderelection.LeaderCallbacks{
		OnStartedLeading: func(leader context.Context) {
			close(workerStarted)
			defer close(workerDone)
			if err := worker.Run(leader); err != nil && !errors.Is(err, context.Canceled) {
				logger.Error("agent worker failed")
				stop()
			}
		}, OnStoppedLeading: func() { stop() },
	}})
	if err != nil {
		return err
	}
	election.Run(ctx)
	select {
	case <-workerStarted:
		select {
		case <-workerDone:
		case <-time.After(65 * time.Second):
			return fmt.Errorf("worker did not stop after leadership ended")
		}
	default:
	}
	return nil
}
