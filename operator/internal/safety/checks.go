// Package safety evaluates live evidence. Unknown evidence never grants disruption permission.
package safety

import (
	"context"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operations "kordex.local/api/operations/v1alpha1"
	"kordex.local/api/protocol"
)

const StatelessLabel = protocol.OperationGroup + "/maintenance"

type Result struct {
	Allowed bool
	Reason  string
}

func Pass() Result               { return Result{Allowed: true, Reason: "SafetyPassed"} }
func Block(reason string) Result { return Result{Reason: reason} }

type Storage interface {
	Check(context.Context, *corev1.Node, []corev1.Pod) (Result, error)
}

// PreCordonPDBStorage identifies only PDBs intentionally managed by a storage
// operator, which may need to observe a cordon before making its decision.
// The controller still checks the same PDB immediately before every eviction.
type PreCordonPDBStorage interface {
	DeferPDBUntilCordon(context.Context, *corev1.Pod, *policyv1.PodDisruptionBudget) (bool, error)
}
type StorageTarget interface {
	SupportsTarget(context.Context, *corev1.Node, []corev1.Pod) (bool, error)
}
type Quorum interface {
	Check(context.Context, *corev1.Node) (Result, error)
}
type APIHealth interface{ Ready(context.Context) error }
type Checker struct {
	Reader  client.Reader
	Storage Storage
	Quorum  Quorum
	API     APIHealth
	Now     func() time.Time
}

func (c *Checker) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}
func ControlPlane(n *corev1.Node) bool {
	_, cp := n.Labels["node-role.kubernetes.io/control-plane"]
	_, master := n.Labels["node-role.kubernetes.io/master"]
	return cp || master
}
func Ready(p *corev1.Pod) bool {
	for _, v := range p.Status.Conditions {
		if v.Type == corev1.PodReady {
			return v.Status == corev1.ConditionTrue
		}
	}
	return false
}
func Complete(p *corev1.Pod) bool {
	return p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed
}
func (c *Checker) NodeReady(ctx context.Context, n *corev1.Node) (Result, error) {
	healthy := false
	pressure := 0
	for _, condition := range n.Status.Conditions {
		switch condition.Type {
		case corev1.NodeReady:
			healthy = condition.Status == corev1.ConditionTrue && !condition.LastTransitionTime.IsZero() && !condition.LastTransitionTime.After(c.now().Add(-10*time.Second))
		case corev1.NodeMemoryPressure, corev1.NodeDiskPressure, corev1.NodePIDPressure, corev1.NodeNetworkUnavailable:
			if condition.Status != corev1.ConditionFalse {
				return Block("NodePressureOrUnknown"), nil
			}
			if condition.Type != corev1.NodeNetworkUnavailable {
				pressure++
			}
		}
	}
	if !healthy || pressure < 3 {
		return Block("NodeNotStablyReady"), nil
	}
	var lease coordinationv1.Lease
	if err := c.Reader.Get(ctx, types.NamespacedName{Namespace: "kube-node-lease", Name: n.Name}, &lease); err != nil {
		return Block("NodeHeartbeatUnknown"), nil
	}
	if lease.Spec.RenewTime == nil || c.now().Sub(lease.Spec.RenewTime.Time) > 40*time.Second || lease.Spec.RenewTime.After(c.now().Add(5*time.Second)) {
		return Block("NodeHeartbeatStale"), nil
	}
	return Pass(), nil
}
func (c *Checker) Cluster(ctx context.Context, target string, evictions []operations.EvictionRecord) ([]corev1.Pod, Result, error) {
	if c.API == nil || c.API.Ready(ctx) != nil {
		return nil, Block("APIServerHealthUnknown"), nil
	}
	var nodes corev1.NodeList
	if err := c.Reader.List(ctx, &nodes); err != nil {
		return nil, Result{}, err
	}
	otherWorkers := 0
	for i := range nodes.Items {
		n := &nodes.Items[i]
		result, err := c.NodeReady(ctx, n)
		if err != nil || !result.Allowed {
			return nil, result, err
		}
		if n.Name != target && n.Spec.Unschedulable {
			return nil, Block("OtherNodeCordoned"), nil
		}
		if n.Name != target && !ControlPlane(n) && !n.Spec.Unschedulable {
			otherWorkers++
		}
	}
	if otherWorkers == 0 {
		return nil, Block("NoAvailableWorkerPeer"), nil
	}
	var deployments appsv1.DeploymentList
	if err := c.Reader.List(ctx, &deployments); err != nil {
		return nil, Result{}, err
	}
	for i := range deployments.Items {
		if !deploymentHealthy(&deployments.Items[i]) {
			return nil, Block("ClusterDeploymentDegraded"), nil
		}
	}
	var pods corev1.PodList
	if err := c.Reader.List(ctx, &pods); err != nil {
		return nil, Result{}, err
	}
	own := map[types.UID]bool{}
	for _, e := range evictions {
		own[types.UID(e.UID)] = true
	}
	for i := range pods.Items {
		p := &pods.Items[i]
		if Complete(p) {
			continue
		}
		if !p.DeletionTimestamp.IsZero() && own[p.UID] {
			continue
		}
		if !p.DeletionTimestamp.IsZero() || !Ready(p) {
			return pods.Items, Block("ClusterWorkloadDegraded"), nil
		}
	}
	return pods.Items, Pass(), nil
}
func (c *Checker) Preflight(ctx context.Context, n *corev1.Node, p *operations.MaintenancePolicy, evictions []operations.EvictionRecord) ([]corev1.Pod, Result, error) {
	if p.Spec.RecoverySeconds < 10 || p.Spec.RecoverySeconds > 300 || p.Spec.GracePeriodSeconds < 1 || p.Spec.GracePeriodSeconds > 120 {
		return nil, Block("InvalidPolicyLimits"), nil
	}
	if p.Spec.AllowGKESystemWorkloads && (p.Spec.GKESystemWorkloadMinAvailable < 0 || p.Spec.GKESystemWorkloadMinAvailable > 10) {
		return nil, Block("InvalidGKESystemWorkloadLimits"), nil
	}
	if p.Spec.Suspended {
		return nil, Block("PolicySuspended"), nil
	}
	selector, err := metav1.LabelSelectorAsSelector(&p.Spec.NodeSelector)
	if err != nil {
		return nil, Block("InvalidNodeSelector"), nil
	}
	if !selector.Matches(labels.Set(n.Labels)) {
		return nil, Block("PolicySelectorMismatch"), nil
	}
	statelessOptIn := n.Labels[StatelessLabel] == "stateless"
	if !statelessOptIn {
		storageTarget, ok := c.Storage.(StorageTarget)
		if !ok {
			return nil, Block("StatelessWorkerOptInRequired"), nil
		}
		var targetPods corev1.PodList
		if err := c.Reader.List(ctx, &targetPods, client.MatchingFields{"spec.nodeName": n.Name}); err != nil {
			return nil, Result{}, err
		}
		supported, err := storageTarget.SupportsTarget(ctx, n, targetPods.Items)
		if err != nil {
			return nil, Result{}, err
		}
		if !supported {
			return nil, Block("StatelessWorkerOptInRequired"), nil
		}
	}
	if c.Quorum == nil {
		return nil, Block("QuorumUnknown"), nil
	}
	q, err := c.Quorum.Check(ctx, n)
	if err != nil || !q.Allowed {
		return nil, q, err
	}
	pods, result, err := c.Cluster(ctx, n.Name, evictions)
	if err != nil || !result.Allowed {
		return nil, result, err
	}
	storagePods := make([]corev1.Pod, 0, len(pods))
	gkeWorkloads := make(map[types.UID]bool)
	ownedEvictions := make(map[types.UID]struct{}, len(evictions))
	for _, eviction := range evictions {
		ownedEvictions[types.UID(eviction.UID)] = struct{}{}
	}
	for i := range pods {
		pod := &pods[i]
		if pod.Spec.NodeName != n.Name || Complete(pod) {
			storagePods = append(storagePods, *pod)
			continue
		}
		if !pod.DeletionTimestamp.IsZero() {
			if _, owned := ownedEvictions[pod.UID]; owned {
				continue
			}
		}
		if isGKEKubeProxyMirror(pod, n) {
			continue
		}
		if _, mirror := pod.Annotations[corev1.MirrorPodAnnotationKey]; mirror {
			return nil, Block("MirrorPodNotEvictable"), nil
		}
		if _, isGKEAddon, err := c.gkeDeploymentForPod(ctx, pod, n); err != nil {
			return nil, Result{}, err
		} else if isGKEAddon {
			gkeResult, err := c.gkeSystemWorkloadEvidence(ctx, pod, n, p)
			if err != nil || !gkeResult.Allowed {
				return nil, gkeResult, err
			}
			gkeWorkloads[pod.UID] = true
			continue
		}
		storagePods = append(storagePods, *pod)
	}
	if c.Storage == nil {
		return nil, Block("StorageUnknown"), nil
	}
	result, err = c.Storage.Check(ctx, n, storagePods)
	if err != nil || !result.Allowed {
		return nil, result, err
	}
	candidates := []corev1.Pod{}
	for i := range pods {
		pod := &pods[i]
		if pod.Spec.NodeName != n.Name || Complete(pod) {
			continue
		}
		if _, mirror := pod.Annotations[corev1.MirrorPodAnnotationKey]; mirror {
			if isGKEKubeProxyMirror(pod, n) {
				continue
			}
			return nil, Block("MirrorPodNotEvictable"), nil
		}
		owner := metav1.GetControllerOf(pod)
		if owner != nil && owner.Kind == "DaemonSet" && owner.APIVersion == "apps/v1" {
			var ds appsv1.DaemonSet
			if err = c.Reader.Get(ctx, types.NamespacedName{Namespace: pod.Namespace, Name: owner.Name}, &ds); err != nil || ds.UID != owner.UID {
				return nil, Block("DaemonSetOwnerUnknown"), nil
			}
			continue
		}
		if !pod.DeletionTimestamp.IsZero() {
			continue
		}
		if strings.HasPrefix(pod.Spec.PriorityClassName, "system-") && !gkeWorkloads[pod.UID] {
			return nil, Block("CriticalWorkloadOnTarget"), nil
		}
		if pod.Namespace == p.Namespace {
			return nil, Block("ManagementWorkloadOnTarget"), nil
		}
		if _, result, err = c.Workload(ctx, pod); err != nil || !result.Allowed {
			return nil, result, err
		}
		candidates = append(candidates, *pod)
	}
	if len(candidates)+len(evictions) > 128 {
		return nil, Block("TooManyEvictions"), nil
	}
	return candidates, Pass(), nil
}

// PDBBeforeCordon defers only PDBs identified by an enabled storage-native
// disruption manager. Ordinary and unknown PDBs retain the normal gate.
func (c *Checker) PDBBeforeCordon(ctx context.Context, pod *corev1.Pod) (Result, error) {
	var budgets policyv1.PodDisruptionBudgetList
	if err := c.Reader.List(ctx, &budgets, client.InNamespace(pod.Namespace)); err != nil {
		return Result{}, err
	}
	matches := 0
	for i := range budgets.Items {
		pdb := &budgets.Items[i]
		selector, err := metav1.LabelSelectorAsSelector(pdb.Spec.Selector)
		if err != nil {
			return Block("PDBSelectorUnknown"), nil
		}
		if !selector.Matches(labels.Set(pod.Labels)) {
			continue
		}
		matches++
		deferCheck := false
		if storage, ok := c.Storage.(PreCordonPDBStorage); ok {
			deferCheck, err = storage.DeferPDBUntilCordon(ctx, pod, pdb)
			if err != nil {
				return Result{}, err
			}
		}
		if deferCheck {
			continue
		}
		if pdb.Status.ObservedGeneration < pdb.Generation || pdb.Status.DisruptionsAllowed < 1 {
			return Block("PDBBlocked"), nil
		}
	}
	if matches == 0 {
		return Block("PDBRequired"), nil
	}
	if matches > 1 {
		return Block("OverlappingPDBs"), nil
	}
	return Pass(), nil
}
func (c *Checker) Workload(ctx context.Context, pod *corev1.Pod) (operations.WorkloadReference, Result, error) {
	var ref operations.WorkloadReference
	owner := metav1.GetControllerOf(pod)
	if owner == nil || owner.Kind != "ReplicaSet" || owner.APIVersion != "apps/v1" {
		return ref, Block("UnsupportedOrUnmanagedWorkload"), nil
	}
	var rs appsv1.ReplicaSet
	if err := c.Reader.Get(ctx, types.NamespacedName{Namespace: pod.Namespace, Name: owner.Name}, &rs); err != nil {
		return ref, Result{}, err
	}
	if rs.UID != owner.UID {
		return ref, Block("WorkloadIdentityChanged"), nil
	}
	deployment := metav1.GetControllerOf(&rs)
	if deployment == nil || deployment.Kind != "Deployment" || deployment.APIVersion != "apps/v1" {
		return ref, Block("DeploymentOwnerRequired"), nil
	}
	var d appsv1.Deployment
	if err := c.Reader.Get(ctx, types.NamespacedName{Namespace: pod.Namespace, Name: deployment.Name}, &d); err != nil {
		return ref, Result{}, err
	}
	if d.UID != deployment.UID {
		return ref, Block("WorkloadIdentityChanged"), nil
	}
	replicas := int32(1)
	if d.Spec.Replicas != nil {
		replicas = *d.Spec.Replicas
	}
	ref = operations.WorkloadReference{Namespace: d.Namespace, Name: d.Name, UID: string(d.UID), Replicas: replicas}
	result, err := c.Recovered(ctx, ref)
	return ref, result, err
}
func (c *Checker) Recovered(ctx context.Context, ref operations.WorkloadReference) (Result, error) {
	var d appsv1.Deployment
	if err := c.Reader.Get(ctx, types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}, &d); err != nil {
		return Result{}, err
	}
	desired := int32(1)
	if d.Spec.Replicas != nil {
		desired = *d.Spec.Replicas
	}
	if string(d.UID) != ref.UID || desired < ref.Replicas {
		return Block("WorkloadIdentityOrScaleChanged"), nil
	}
	if !deploymentHealthy(&d) {
		return Block("WorkloadRecoveryPending"), nil
	}
	return Pass(), nil
}
func deploymentHealthy(d *appsv1.Deployment) bool {
	desired := int32(1)
	if d.Spec.Replicas != nil {
		desired = *d.Spec.Replicas
	}
	return d.Status.ObservedGeneration >= d.Generation && d.Status.AvailableReplicas >= desired && d.Status.UpdatedReplicas >= desired && d.Status.ReadyReplicas >= desired && d.Status.Replicas == desired
}

func (c *Checker) PDB(ctx context.Context, pod *corev1.Pod) (Result, error) {
	var budgets policyv1.PodDisruptionBudgetList
	if err := c.Reader.List(ctx, &budgets, client.InNamespace(pod.Namespace)); err != nil {
		return Result{}, err
	}
	matches := 0
	for i := range budgets.Items {
		pdb := &budgets.Items[i]
		selector, err := metav1.LabelSelectorAsSelector(pdb.Spec.Selector)
		if err != nil {
			return Block("PDBSelectorUnknown"), nil
		}
		if !selector.Matches(labels.Set(pod.Labels)) {
			continue
		}
		matches++
		if pdb.Status.ObservedGeneration < pdb.Generation || pdb.Status.DisruptionsAllowed < 1 {
			return Block("PDBBlocked"), nil
		}
	}
	if matches == 0 {
		return Block("PDBRequired"), nil
	}
	if matches > 1 {
		return Block("OverlappingPDBs"), nil
	}
	return Pass(), nil
}

// StatelessStorage blocks storage attached to the target node, local PVs placed on
// it, and clusters whose storage health cannot be established. Unrelated remote
// PVs elsewhere in the cluster do not by themselves block a worker operation.
type StatelessStorage struct{ Reader client.Reader }

func (s StatelessStorage) Check(ctx context.Context, n *corev1.Node, pods []corev1.Pod) (Result, error) {
	for _, key := range []string{"node-role.kubernetes.io/storage", "node-role.kubernetes.io/ceph"} {
		if _, ok := n.Labels[key]; ok {
			return Block("StorageNodeAdapterRequired"), nil
		}
	}
	var volumes corev1.PersistentVolumeList
	if err := s.Reader.List(ctx, &volumes); err != nil {
		return Result{}, err
	}
	for i := range volumes.Items {
		volume := &volumes.Items[i]
		if volume.Spec.Local == nil {
			continue
		}
		matches, known := localPVTargetsNode(volume, n)
		if !known {
			return Block("LocalPVPlacementUnknown"), nil
		}
		if matches {
			return Block("NodeLocalPersistentVolumePresent"), nil
		}
	}
	for i := range pods {
		pod := &pods[i]
		if Complete(pod) {
			continue
		}
		if isGKEKubeProxyMirror(pod, n) {
			continue
		}
		for _, label := range []string{pod.Namespace, pod.Labels["app"], pod.Labels["app.kubernetes.io/name"]} {
			value := strings.ToLower(label)
			for _, name := range []string{"rook-ceph", "longhorn", "openebs", "linstor"} {
				if strings.Contains(value, name) {
					return Block("StorageHealthUnknown"), nil
				}
			}
		}
		if pod.Spec.NodeName != n.Name {
			continue
		}
		// DaemonSets remain running during a drain drill; their host mounts are not evicted.
		owner := metav1.GetControllerOf(pod)
		if owner != nil && owner.Kind == "DaemonSet" {
			continue
		}
		for _, v := range pod.Spec.Volumes {
			if v.PersistentVolumeClaim != nil {
				return Block("PersistentVolumeUsedOnTargetNode"), nil
			}
			if v.HostPath != nil || v.EmptyDir != nil || v.Ephemeral != nil || v.CSI != nil {
				return Block("LocalOrPersistentDataPresent"), nil
			}
		}
	}
	return Pass(), nil
}

// localPVTargetsNode evaluates the required PV node affinity against the node's
// labels and metadata.name field. Unsupported or malformed requirements return
// known=false so callers fail closed instead of guessing placement.
func localPVTargetsNode(volume *corev1.PersistentVolume, node *corev1.Node) (matches, known bool) {
	affinity := volume.Spec.NodeAffinity
	if affinity == nil || affinity.Required == nil || len(affinity.Required.NodeSelectorTerms) == 0 {
		return false, false
	}
	values := map[string]string{"metadata.name": node.Name}
	for key, value := range node.Labels {
		values[key] = value
	}
	for _, term := range affinity.Required.NodeSelectorTerms {
		if len(term.MatchExpressions) == 0 && len(term.MatchFields) == 0 {
			continue
		}
		selector := metav1.LabelSelector{MatchExpressions: make([]metav1.LabelSelectorRequirement, 0, len(term.MatchExpressions)+len(term.MatchFields))}
		for _, requirement := range term.MatchExpressions {
			selector.MatchExpressions = append(selector.MatchExpressions, metav1.LabelSelectorRequirement{Key: requirement.Key, Operator: metav1.LabelSelectorOperator(requirement.Operator), Values: requirement.Values})
		}
		for _, requirement := range term.MatchFields {
			if requirement.Key != "metadata.name" {
				return false, false
			}
			selector.MatchExpressions = append(selector.MatchExpressions, metav1.LabelSelectorRequirement{Key: requirement.Key, Operator: metav1.LabelSelectorOperator(requirement.Operator), Values: requirement.Values})
		}
		parsed, err := metav1.LabelSelectorAsSelector(&selector)
		if err != nil {
			return false, false
		}
		if parsed.Matches(labels.Set(values)) {
			return true, true
		}
	}
	return false, true
}

type WorkerOnlyQuorum struct{}

func (WorkerOnlyQuorum) Check(_ context.Context, n *corev1.Node) (Result, error) {
	if ControlPlane(n) {
		return Block("ControlPlaneQuorumAdapterRequired"), nil
	}
	return Pass(), nil
}

// AllRecovered is used before another eviction and before restoring schedulability.
func (c *Checker) AllRecovered(ctx context.Context, evictions []operations.EvictionRecord) (Result, error) {
	for _, e := range evictions {
		result, err := c.Recovered(ctx, e.Workload)
		if err != nil || !result.Allowed {
			return result, err
		}
	}
	return Pass(), nil
}

// AllRecoveredAfterCancellation verifies the currently declared Deployment
// state after a signed cancellation. It permits an autoscaler to reduce the
// desired replica count, but still requires the same Deployment identity and
// every currently desired replica to be healthy before recovery can uncordon.
func (c *Checker) AllRecoveredAfterCancellation(ctx context.Context, evictions []operations.EvictionRecord) (Result, error) {
	for _, eviction := range evictions {
		var deployment appsv1.Deployment
		if err := c.Reader.Get(ctx, types.NamespacedName{Namespace: eviction.Workload.Namespace, Name: eviction.Workload.Name}, &deployment); err != nil {
			return Result{}, err
		}
		if string(deployment.UID) != eviction.Workload.UID {
			return Block("WorkloadIdentityChanged"), nil
		}
		if !deploymentHealthy(&deployment) {
			return Block("WorkloadRecoveryPending"), nil
		}
	}
	return Pass(), nil
}
