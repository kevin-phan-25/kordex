package safety

import (
	"context"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var rookCephClusters = schema.GroupVersionResource{Group: "ceph.rook.io", Version: "v1", Resource: "cephclusters"}

// RookCephStorage is a read-only safety adapter for Rook-managed Ceph. It uses
// Rook's periodically refreshed CephCluster status, manager metrics, and
// Kubernetes OSD pod readiness/placement. It never changes Ceph flags or
// performs storage maintenance.
// OSD-host maintenance remains blocked until an ownership-aware Ceph workflow
// is configured.
type RookCephStorage struct {
	Reader  client.Reader
	Dynamic dynamic.Interface
	Metrics RookMetricsSource
	Now     func() time.Time
}

// DeferPDBUntilCordon handles only Rook's canonical managed OSD budget. Rook
// observes a node drain before it recalculates that budget. This exception is
// used only by the pre-cordon gate; eviction still uses Checker.PDB.
func (s RookCephStorage) DeferPDBUntilCordon(ctx context.Context, pod *corev1.Pod, pdb *policyv1.PodDisruptionBudget) (bool, error) {
	if pod == nil || pdb == nil || pod.Namespace == "" || pod.Namespace != pdb.Namespace ||
		pod.Labels["app"] != "rook-ceph-osd" || pdb.Name != "rook-ceph-osd" ||
		pod.Labels["ceph-osd-id"] == "" || pdb.Labels["app"] != "rook-ceph-osd" {
		return false, nil
	}
	if _, err := strconv.ParseUint(pod.Labels["ceph-osd-id"], 10, 32); err != nil {
		return false, nil
	}
	if s.Dynamic == nil {
		return false, nil
	}
	_, managed, err := s.managedClusterForNamespace(ctx, pod.Namespace)
	if err != nil {
		return false, err
	}
	if !managed {
		return false, nil
	}
	selector, err := metav1.LabelSelectorAsSelector(pdb.Spec.Selector)
	if err != nil || !selector.Matches(labels.Set(pod.Labels)) {
		return false, nil
	}
	return true, nil
}

func (s RookCephStorage) SupportsTarget(ctx context.Context, node *corev1.Node, pods []corev1.Pod) (bool, error) {
	if node == nil || s.Dynamic == nil {
		return false, nil
	}
	for i := range pods {
		pod := &pods[i]
		if pod.Spec.NodeName != node.Name || pod.Labels["app"] != "rook-ceph-osd" || pod.Labels["ceph-osd-id"] == "" {
			continue
		}
		if _, err := strconv.ParseUint(pod.Labels["ceph-osd-id"], 10, 32); err != nil {
			continue
		}
		_, managed, err := s.managedClusterForNamespace(ctx, pod.Namespace)
		if err != nil {
			return false, err
		}
		if managed {
			return true, nil
		}
	}
	return false, nil
}

func (s RookCephStorage) managedClusterForNamespace(ctx context.Context, namespace string) (*unstructured.Unstructured, bool, error) {
	if s.Dynamic == nil || namespace == "" {
		return nil, false, nil
	}
	clusters, err := s.Dynamic.Resource(rookCephClusters).Namespace(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, false, err
	}
	if len(clusters.Items) != 1 {
		return nil, false, nil
	}
	cluster := &clusters.Items[0]
	managePDBs, found, err := unstructured.NestedBool(cluster.Object, "spec", "disruptionManagement", "managePodBudgets")
	if err != nil || !found || !managePDBs {
		return nil, false, nil
	}
	observedGeneration, found, err := unstructured.NestedInt64(cluster.Object, "status", "observedGeneration")
	if err != nil || !found || observedGeneration < cluster.GetGeneration() {
		return nil, false, nil
	}
	return cluster, true, nil
}

func (s RookCephStorage) Check(ctx context.Context, node *corev1.Node, pods []corev1.Pod) (Result, error) {
	if node == nil || s.Dynamic == nil || s.Reader == nil {
		return Block("CephEvidenceUnknown"), nil
	}
	clusters, err := s.Dynamic.Resource(rookCephClusters).List(ctx, metav1.ListOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) && !hasRookFootprint(node, pods) {
			return StatelessStorage{Reader: s.Reader}.Check(ctx, node, pods)
		}
		return Block("RookCephStatusUnavailable"), nil
	}
	if len(clusters.Items) == 0 {
		if hasRookFootprint(node, pods) {
			return Block("RookCephClusterIdentityUnknown"), nil
		}
		return StatelessStorage{Reader: s.Reader}.Check(ctx, node, pods)
	}

	now := time.Now()
	if s.Now != nil {
		now = s.Now()
	}
	for i := range clusters.Items {
		cluster := &clusters.Items[i]
		if result := evaluateRookCluster(cluster, now); !result.Allowed {
			return result, nil
		}
		if result := s.checkCephState(ctx, cluster, node, now); !result.Allowed {
			return result, nil
		}
	}
	return StatelessStorage{Reader: s.Reader}.Check(ctx, node, withoutRookInfrastructure(pods))
}

func evaluateRookCluster(cluster *unstructured.Unstructured, now time.Time) Result {
	if cluster == nil || cluster.GetName() == "" || cluster.GetNamespace() == "" {
		return Block("RookCephClusterIdentityUnknown")
	}
	observedGeneration, found, err := unstructured.NestedInt64(cluster.Object, "status", "observedGeneration")
	if err != nil || !found || observedGeneration < cluster.GetGeneration() {
		return Block("RookCephGenerationNotObserved")
	}
	health, found, err := unstructured.NestedString(cluster.Object, "status", "ceph", "health")
	if err != nil || !found || health == "" {
		return Block("RookCephHealthUnknown")
	}
	if health != "HEALTH_OK" {
		return Block("RookCephHealthNotOK")
	}
	checked, found, err := unstructured.NestedString(cluster.Object, "status", "ceph", "lastChecked")
	if err != nil || !found || checked == "" {
		return Block("RookCephEvidenceTimestampUnknown")
	}
	observedAt, err := time.Parse(time.RFC3339, checked)
	if err != nil || observedAt.After(now.Add(5*time.Second)) || now.Sub(observedAt) > 2*time.Minute {
		return Block("RookCephEvidenceStale")
	}
	state, found, err := unstructured.NestedString(cluster.Object, "status", "state")
	if err != nil || !found || (state != "Created" && state != "Connected") {
		return Block("RookCephOperatorStateUnknown")
	}
	return Pass()
}

func (s RookCephStorage) checkCephState(ctx context.Context, cluster *unstructured.Unstructured, target *corev1.Node, now time.Time) Result {
	if s.Metrics == nil {
		return Block("RookCephMetricsSourceUnavailable")
	}
	storeTypes, found, err := unstructured.NestedMap(cluster.Object, "status", "storage", "osd", "storeType")
	if err != nil || !found || len(storeTypes) == 0 {
		return Block("RookCephOSDCountUnknown")
	}
	expected, ok := sumOSDStoreTypes(storeTypes)
	if !ok {
		return Block("RookCephOSDCountInvalid")
	}
	if expected < 1 {
		return Block("RookCephOSDCountUnknown")
	}
	var osdPods corev1.PodList
	if err := s.Reader.List(ctx, &osdPods,
		client.InNamespace(cluster.GetNamespace()),
		client.MatchingLabels{"app": "rook-ceph-osd"},
	); err != nil {
		return Block("RookCephOSDInventoryUnavailable")
	}
	if int64(len(osdPods.Items)) != expected {
		return Block("RookCephOSDInventoryMismatch")
	}
	podIDs := make(map[string]struct{}, len(osdPods.Items))
	for i := range osdPods.Items {
		pod := &osdPods.Items[i]
		if pod.Spec.NodeName == "" || pod.Status.Phase != corev1.PodRunning || !podReady(pod) {
			return Block("RookCephOSDNotReady")
		}
		osdID := pod.Labels["ceph-osd-id"]
		if osdID == "" {
			return Block("RookCephOSDIdentityUnknown")
		}
		if _, exists := podIDs[osdID]; exists {
			return Block("RookCephOSDIdentityContradictory")
		}
		podIDs[osdID] = struct{}{}
		if pod.Spec.NodeName == target.Name {
			return Block("CephOSDHostMaintenanceAdapterRequired")
		}
	}
	metrics, err := s.Metrics.Scrape(ctx, cluster.GetNamespace())
	if err != nil {
		return Block("RookCephMetricsUnavailable")
	}
	return evaluateRookMetricsAt(metrics, podIDs, now)
}

func sumOSDStoreTypes(storeTypes map[string]interface{}) (int64, bool) {
	total := int64(0)
	for _, value := range storeTypes {
		count, ok := integralCount(value)
		if !ok || count < 0 || count > int64(^uint64(0)>>1)-total {
			return 0, false
		}
		total += count
	}
	return total, true
}

func integralCount(value interface{}) (int64, bool) {
	switch count := value.(type) {
	case int:
		return int64(count), true
	case int32:
		return int64(count), true
	case int64:
		return count, true
	default:
		return 0, false
	}
}

func podReady(pod *corev1.Pod) bool {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady {
			return condition.Status == corev1.ConditionTrue
		}
	}
	return false
}

func hasRookFootprint(node *corev1.Node, pods []corev1.Pod) bool {
	for _, key := range []string{"node-role.kubernetes.io/storage", "node-role.kubernetes.io/ceph"} {
		if _, found := node.Labels[key]; found {
			return true
		}
	}
	for i := range pods {
		pod := &pods[i]
		app := strings.ToLower(pod.Labels["app"])
		if strings.HasPrefix(app, "rook-ceph") || pod.Labels["ceph.rook.io/cluster"] != "" || strings.Contains(strings.ToLower(pod.Namespace), "rook-ceph") {
			return true
		}
		for _, volume := range pod.Spec.Volumes {
			if volume.CSI != nil && (strings.Contains(volume.CSI.Driver, "ceph") || strings.Contains(volume.CSI.Driver, "rook")) {
				return true
			}
		}
	}
	return false
}

func withoutRookInfrastructure(pods []corev1.Pod) []corev1.Pod {
	filtered := make([]corev1.Pod, 0, len(pods))
	for i := range pods {
		pod := &pods[i]
		app := strings.ToLower(pod.Labels["app"])
		if strings.HasPrefix(app, "rook-ceph") || pod.Labels["ceph.rook.io/cluster"] != "" || strings.Contains(strings.ToLower(pod.Namespace), "rook-ceph") {
			continue
		}
		filtered = append(filtered, *pod)
	}
	return filtered
}
