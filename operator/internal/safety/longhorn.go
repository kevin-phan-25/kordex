package safety

import (
	"context"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	longhornNodes    = schema.GroupVersionResource{Group: "longhorn.io", Version: "v1beta2", Resource: "nodes"}
	longhornVolumes  = schema.GroupVersionResource{Group: "longhorn.io", Version: "v1beta2", Resource: "volumes"}
	longhornReplicas = schema.GroupVersionResource{Group: "longhorn.io", Version: "v1beta2", Resource: "replicas"}
)

// LonghornStorage reads the Longhorn v1beta2 node, volume, and replica APIs.
// It does not change scheduling, evict replicas, or coordinate rebuilds.
// Therefore Longhorn service nodes and nodes hosting replicas remain blocked.
type LonghornStorage struct {
	Reader  client.Reader
	Dynamic dynamic.Interface
	Now     func() time.Time
}

func (s LonghornStorage) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s LonghornStorage) Check(ctx context.Context, target *corev1.Node, pods []corev1.Pod) (Result, error) {
	if target == nil || s.Reader == nil || s.Dynamic == nil {
		return Block("LonghornEvidenceUnavailable"), nil
	}
	for i := range pods {
		if pods[i].Spec.NodeName == target.Name && longhornStoragePod(&pods[i]) {
			return Block("LonghornMaintenanceWorkflowRequired"), nil
		}
	}

	var pvs corev1.PersistentVolumeList
	if err := s.Reader.List(ctx, &pvs); err != nil {
		return Block("LonghornPVEvidenceUnavailable"), nil
	}
	footprint := hasLonghornFootprint(target, pods, pvs.Items)

	nodes, nodeErr := s.Dynamic.Resource(longhornNodes).List(ctx, metav1.ListOptions{})
	volumes, volumeErr := s.Dynamic.Resource(longhornVolumes).List(ctx, metav1.ListOptions{})
	replicas, replicaErr := s.Dynamic.Resource(longhornReplicas).List(ctx, metav1.ListOptions{})
	for _, err := range []error{nodeErr, volumeErr, replicaErr} {
		if err == nil {
			continue
		}
		if apierrors.IsNotFound(err) && !footprint {
			return Pass(), nil
		}
		return Block("LonghornEvidenceUnavailable"), nil
	}
	if len(nodes.Items) == 0 && len(volumes.Items) == 0 && len(replicas.Items) == 0 && !footprint {
		return Pass(), nil
	}
	if len(nodes.Items) == 0 {
		return Block("LonghornNodeInventoryUnknown"), nil
	}
	sort.Slice(nodes.Items, func(i, j int) bool { return nodes.Items[i].GetName() < nodes.Items[j].GetName() })
	sort.Slice(volumes.Items, func(i, j int) bool { return volumes.Items[i].GetName() < volumes.Items[j].GetName() })
	sort.Slice(replicas.Items, func(i, j int) bool { return replicas.Items[i].GetName() < replicas.Items[j].GetName() })

	now := s.now()
	nodeByName := make(map[string]*unstructured.Unstructured, len(nodes.Items))
	for i := range nodes.Items {
		lhNode := &nodes.Items[i]
		name := lhNode.GetName()
		if name == "" || lhNode.GetNamespace() == "" {
			return Block("LonghornNodeIdentityUnknown"), nil
		}
		if _, exists := nodeByName[name]; exists {
			return Block("LonghornNodeIdentityContradictory"), nil
		}
		if result := evaluateLonghornNode(lhNode, now); !result.Allowed {
			return result, nil
		}
		nodeByName[name] = lhNode
	}
	if _, found := nodeByName[target.Name]; !found {
		return Block("LonghornTargetNodeUnknown"), nil
	}

	volumeByName := make(map[string]*unstructured.Unstructured, len(volumes.Items))
	for i := range volumes.Items {
		volume := &volumes.Items[i]
		if volume.GetName() == "" || volume.GetNamespace() == "" {
			return Block("LonghornVolumeIdentityUnknown"), nil
		}
		if _, exists := volumeByName[volume.GetName()]; exists {
			return Block("LonghornVolumeIdentityContradictory"), nil
		}
		volumeByName[volume.GetName()] = volume
	}
	replicasByVolume := make(map[string][]*unstructured.Unstructured, len(volumeByName))
	for i := range replicas.Items {
		replica := &replicas.Items[i]
		volumeName, found, err := unstructured.NestedString(replica.Object, "spec", "volumeName")
		if err != nil || !found || volumeName == "" || volumeByName[volumeName] == nil {
			return Block("LonghornReplicaIdentityUnknown"), nil
		}
		replicasByVolume[volumeName] = append(replicasByVolume[volumeName], replica)
	}

	volumeNames := make([]string, 0, len(volumeByName))
	for name := range volumeByName {
		volumeNames = append(volumeNames, name)
	}
	sort.Strings(volumeNames)
	for _, name := range volumeNames {
		if result := evaluateLonghornVolume(volumeByName[name], replicasByVolume[name], nodeByName, target.Name, now); !result.Allowed {
			return result, nil
		}
	}
	return Pass(), nil
}

func evaluateLonghornNode(node *unstructured.Unstructured, now time.Time) Result {
	conditions, found, err := unstructured.NestedSlice(node.Object, "status", "conditions")
	if err != nil || !found {
		return Block("LonghornNodeHealthUnknown")
	}
	for _, item := range conditions {
		condition, ok := item.(map[string]interface{})
		if !ok {
			return Block("LonghornNodeHealthUnknown")
		}
		typ, _ := condition["type"].(string)
		if typ != "Ready" {
			continue
		}
		status, _ := condition["status"].(string)
		probe, _ := condition["lastProbeTime"].(string)
		checkedAt, parseErr := time.Parse(time.RFC3339, probe)
		if status != "True" {
			return Block("LonghornNodeNotReady")
		}
		if parseErr != nil || checkedAt.After(now.Add(5*time.Second)) || now.Sub(checkedAt) > 2*time.Minute {
			return Block("LonghornNodeEvidenceStale")
		}
		return Pass()
	}
	return Block("LonghornNodeHealthUnknown")
}

func evaluateLonghornVolume(volume *unstructured.Unstructured, replicas []*unstructured.Unstructured, nodes map[string]*unstructured.Unstructured, target string, now time.Time) Result {
	state, stateFound, stateErr := unstructured.NestedString(volume.Object, "status", "state")
	robustness, robustFound, robustErr := unstructured.NestedString(volume.Object, "status", "robustness")
	desired, desiredFound, desiredErr := unstructured.NestedInt64(volume.Object, "spec", "numberOfReplicas")
	if stateErr != nil || robustErr != nil || desiredErr != nil || !stateFound || !robustFound || !desiredFound || desired < 1 {
		return Block("LonghornVolumeHealthUnknown")
	}
	dataLayout, layoutFound, layoutErr := unstructured.NestedString(volume.Object, "spec", "dataLayout")
	if layoutErr != nil || (layoutFound && dataLayout != "" && dataLayout != "v1") {
		return Block("LonghornDataLayoutUnsupported")
	}
	if migration, found, err := unstructured.NestedString(volume.Object, "status", "currentMigrationNodeID"); err != nil || (found && migration != "") {
		return Block("LonghornMigrationInProgress")
	}
	if restoring, found, err := unstructured.NestedBool(volume.Object, "status", "restoreStatus", "isRestoring"); err != nil || (found && restoring) {
		return Block("LonghornRestoreInProgress")
	}
	if rebuilds, found, err := unstructured.NestedMap(volume.Object, "status", "rebuildStatus"); err != nil {
		return Block("LonghornRebuildEvidenceUnknown")
	} else if found {
		rebuildNames := make([]string, 0, len(rebuilds))
		for name := range rebuilds {
			rebuildNames = append(rebuildNames, name)
		}
		sort.Strings(rebuildNames)
		for _, name := range rebuildNames {
			item := rebuilds[name]
			status, ok := item.(map[string]interface{})
			if !ok {
				return Block("LonghornRebuildEvidenceUnknown")
			}
			rebuilding, ok := status["isRebuilding"].(bool)
			if !ok {
				return Block("LonghornRebuildEvidenceUnknown")
			}
			if rebuilding {
				return Block("LonghornRebuildInProgress")
			}
		}
	}

	currentNode, _, currentNodeErr := unstructured.NestedString(volume.Object, "status", "currentNodeID")
	if currentNodeErr != nil {
		return Block("LonghornVolumeAttachmentUnknown")
	}
	if currentNode == target {
		return Block("LonghornVolumeAttachedToTarget")
	}
	if state == "attached" && (currentNode == "" || nodes[currentNode] == nil) {
		return Block("LonghornVolumeAttachmentUnknown")
	}
	if state == "detached" && currentNode != "" {
		return Block("LonghornVolumeAttachmentUnknown")
	}
	if int64(len(replicas)) != desired {
		return Block("LonghornReplicaCountMismatch")
	}
	seenNodes := make(map[string]struct{}, len(replicas))
	for _, replica := range replicas {
		nodeID, found, err := unstructured.NestedString(replica.Object, "spec", "nodeID")
		if err != nil || !found || nodeID == "" || nodes[nodeID] == nil {
			return Block("LonghornReplicaNodeUnknown")
		}
		if nodeID == target {
			return Block("LonghornReplicaOnTarget")
		}
		if _, duplicate := seenNodes[nodeID]; duplicate {
			return Block("LonghornReplicaPlacementContradictory")
		}
		seenNodes[nodeID] = struct{}{}
		failedAt, failedFound, failedErr := unstructured.NestedString(replica.Object, "spec", "failedAt")
		healthyAt, healthyFound, healthyErr := unstructured.NestedString(replica.Object, "spec", "healthyAt")
		if failedErr != nil || healthyErr != nil || (failedFound && failedAt != "") || !healthyFound || healthyAt == "" {
			return Block("LonghornReplicaHealthUnknown")
		}
		healthySince, parseErr := time.Parse(time.RFC3339, healthyAt)
		if parseErr != nil || healthySince.After(now.Add(5*time.Second)) {
			return Block("LonghornReplicaHealthUnknown")
		}
		currentState, found, err := unstructured.NestedString(replica.Object, "status", "currentState")
		if err != nil || !found {
			return Block("LonghornReplicaHealthUnknown")
		}
		if state == "attached" && currentState != "running" {
			return Block("LonghornReplicaNotRunning")
		}
		if state == "detached" && currentState != "stopped" {
			return Block("LonghornReplicaStateUnknown")
		}
	}
	if state == "attached" {
		if robustness != "healthy" {
			return Block("LonghornVolumeNotHealthy")
		}
		return Pass()
	}
	if state == "detached" {
		if robustness != "healthy" && robustness != "unknown" {
			return Block("LonghornVolumeNotHealthy")
		}
		return Pass()
	}
	return Block("LonghornVolumeStateUnknown")
}

func hasLonghornFootprint(node *corev1.Node, pods []corev1.Pod, pvs []corev1.PersistentVolume) bool {
	if node != nil {
		for key := range node.Labels {
			if strings.HasPrefix(key, "node.longhorn.io/") {
				return true
			}
		}
	}
	for i := range pods {
		pod := &pods[i]
		if strings.Contains(strings.ToLower(pod.Namespace), "longhorn") || longhornInfrastructurePod(pod) {
			return true
		}
		for _, volume := range pod.Spec.Volumes {
			if volume.CSI != nil && strings.Contains(strings.ToLower(volume.CSI.Driver), "longhorn") {
				return true
			}
		}
	}
	for i := range pvs {
		pv := &pvs[i]
		if pv.Spec.CSI != nil && strings.Contains(strings.ToLower(pv.Spec.CSI.Driver), "longhorn") {
			return true
		}
		if strings.Contains(strings.ToLower(pv.Annotations["pv.kubernetes.io/provisioned-by"]), "longhorn") {
			return true
		}
	}
	return false
}

func longhornInfrastructurePod(pod *corev1.Pod) bool {
	if pod == nil {
		return false
	}
	if longhornStoragePod(pod) {
		return true
	}
	if pod.Labels["app"] == "longhorn-ui" || pod.Labels["app"] == "longhorn-driver-deployer" ||
		pod.Labels["app"] == "longhorn-conversion-webhook" || pod.Labels["app"] == "longhorn-admission-webhook" ||
		pod.Labels["app"] == "longhorn-recovery-backend" || pod.Labels["longhorn.io/component"] == "engine-image" {
		return true
	}
	return false
}

func withoutLonghornInfrastructure(pods []corev1.Pod) []corev1.Pod {
	filtered := make([]corev1.Pod, 0, len(pods))
	for i := range pods {
		if longhornInfrastructurePod(&pods[i]) {
			continue
		}
		filtered = append(filtered, pods[i])
	}
	return filtered
}
