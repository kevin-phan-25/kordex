package safety

import (
	"context"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operations "kordex.local/api/operations/v1alpha1"
)

var gkeSystemDeployments = map[string]struct{}{
	"kube-dns":                      {},
	"konnectivity-agent":            {},
	"kube-dns-autoscaler":           {},
	"konnectivity-agent-autoscaler": {},
}

var gkeKubeProxyHostPaths = map[string]struct{}{
	"usr-ca-certs":  {},
	"etc-ssl-certs": {},
	"kubeconfig":    {},
	"varlog":        {},
	"iptableslock":  {},
	"lib-modules":   {},
}

func isGKENode(node *corev1.Node) bool {
	return node != nil && strings.HasPrefix(node.Spec.ProviderID, "gce://") &&
		node.Labels["cloud.google.com/gke-nodepool"] != "" &&
		node.Labels["cloud.google.com/gke-os-distribution"] != ""
}

func isGKEReleaseImage(image string) bool {
	parts := strings.SplitN(image, "/", 2)
	if len(parts) != 2 {
		return false
	}
	host, path := parts[0], parts[1]
	return host == "gke.gcr.io" ||
		(strings.HasSuffix(host, "-artifactregistry.gcr.io") && strings.HasPrefix(path, "gke-release/gke-release/"))
}

func isGKEWorkloadName(name string) bool {
	_, ok := gkeSystemDeployments[name]
	return ok
}

// gkeDeploymentForPod identifies an exact, allowlisted GKE kube-system
// Deployment through its live ReplicaSet owner chain. It does not trust pod
// labels alone.
func (c *Checker) gkeDeploymentForPod(ctx context.Context, pod *corev1.Pod, node *corev1.Node) (*appsv1.Deployment, bool, error) {
	if !isGKENode(node) || pod.Namespace != "kube-system" || pod.Spec.NodeName != node.Name {
		return nil, false, nil
	}
	rsOwner := metav1.GetControllerOf(pod)
	if rsOwner == nil || rsOwner.Kind != "ReplicaSet" || rsOwner.APIVersion != "apps/v1" {
		return nil, false, nil
	}
	var rs appsv1.ReplicaSet
	if err := c.Reader.Get(ctx, types.NamespacedName{Namespace: pod.Namespace, Name: rsOwner.Name}, &rs); err != nil {
		return nil, false, err
	}
	if rs.UID != rsOwner.UID {
		return nil, false, nil
	}
	deploymentOwner := metav1.GetControllerOf(&rs)
	if deploymentOwner == nil || deploymentOwner.Kind != "Deployment" || deploymentOwner.APIVersion != "apps/v1" || !isGKEWorkloadName(deploymentOwner.Name) {
		return nil, false, nil
	}
	var deployment appsv1.Deployment
	if err := c.Reader.Get(ctx, types.NamespacedName{Namespace: pod.Namespace, Name: deploymentOwner.Name}, &deployment); err != nil {
		return nil, false, err
	}
	if deployment.UID != deploymentOwner.UID {
		return nil, false, nil
	}
	return &deployment, true, nil
}

// gkeSystemWorkloadEvidence adds a narrow, explicit GKE add-on availability
// contract only when the policy opts in. It does not replace the PDB check;
// every candidate still passes Checker.PDB before validation or eviction.
func (c *Checker) gkeSystemWorkloadEvidence(ctx context.Context, pod *corev1.Pod, node *corev1.Node, policy *operations.MaintenancePolicy) (Result, error) {
	if !policy.Spec.AllowGKESystemWorkloads {
		return Block("GKESystemWorkloadPolicyRequired"), nil
	}
	if pod.Spec.PriorityClassName != "system-cluster-critical" || !Ready(pod) || !pod.DeletionTimestamp.IsZero() {
		return Block("GKESystemWorkloadIdentityUnknown"), nil
	}
	deployment, ok, err := c.gkeDeploymentForPod(ctx, pod, node)
	if err != nil {
		return Result{}, err
	}
	if !ok {
		return Block("GKESystemWorkloadIdentityUnknown"), nil
	}
	for _, container := range deployment.Spec.Template.Spec.Containers {
		if !isGKEReleaseImage(container.Image) {
			return Block("GKESystemWorkloadIdentityUnknown"), nil
		}
	}
	for _, container := range deployment.Spec.Template.Spec.InitContainers {
		if !isGKEReleaseImage(container.Image) {
			return Block("GKESystemWorkloadIdentityUnknown"), nil
		}
	}
	if !deploymentHealthy(deployment) {
		return Block("GKESystemWorkloadDegraded"), nil
	}
	desired := int32(1)
	if deployment.Spec.Replicas != nil {
		desired = *deployment.Spec.Replicas
	}
	minAvailable := policy.Spec.GKESystemWorkloadMinAvailable
	if minAvailable == 0 {
		minAvailable = 1
	}
	if minAvailable < 1 || minAvailable > 10 || desired <= minAvailable {
		return Block("GKESystemWorkloadRedundancyInsufficient"), nil
	}

	var replicaSets appsv1.ReplicaSetList
	if err = c.Reader.List(ctx, &replicaSets, client.InNamespace(deployment.Namespace)); err != nil {
		return Result{}, err
	}
	currentReplicaSets := make(map[types.UID]struct{})
	for i := range replicaSets.Items {
		rs := &replicaSets.Items[i]
		owner := metav1.GetControllerOf(rs)
		if owner == nil || owner.Kind != "Deployment" || owner.UID != deployment.UID || owner.Name != deployment.Name {
			continue
		}
		template := rs.Spec.Template.DeepCopy()
		delete(template.Labels, "pod-template-hash")
		if equality.Semantic.DeepEqual(template, &deployment.Spec.Template) {
			currentReplicaSets[rs.UID] = struct{}{}
		}
	}
	if len(currentReplicaSets) == 0 {
		return Block("GKESystemWorkloadIdentityUnknown"), nil
	}
	var pods corev1.PodList
	if err = c.Reader.List(ctx, &pods, client.InNamespace(deployment.Namespace)); err != nil {
		return Result{}, err
	}
	peerNodes := make(map[string]struct{})
	for i := range pods.Items {
		peer := &pods.Items[i]
		if peer.Spec.NodeName == "" || peer.Spec.NodeName == node.Name || !peer.DeletionTimestamp.IsZero() || !Ready(peer) {
			continue
		}
		owner := metav1.GetControllerOf(peer)
		if owner == nil || owner.Kind != "ReplicaSet" {
			continue
		}
		if _, current := currentReplicaSets[owner.UID]; current {
			peerNodes[peer.Spec.NodeName] = struct{}{}
		}
	}
	if int32(len(peerNodes)) < minAvailable {
		return Block("GKESystemWorkloadRedundancyInsufficient"), nil
	}
	return Pass(), nil
}

// isGKEKubeProxyMirror recognizes only the node's own GKE static kube-proxy
// mirror pod. The pod is retained during this drain-only workflow; it is never
// sent to the eviction API. Host paths are allowlisted because this pod is not
// restarted by DrainAndVerify and is validated as a kubelet mirror pod.
func isGKEKubeProxyMirror(pod *corev1.Pod, node *corev1.Node) bool {
	if !isGKENode(node) || pod.Namespace != "kube-system" || pod.Spec.NodeName != node.Name ||
		pod.Name != "kube-proxy-"+node.Name || pod.Spec.PriorityClassName != "system-node-critical" {
		return false
	}
	annotations := pod.Annotations
	if annotations[corev1.MirrorPodAnnotationKey] == "" ||
		annotations[corev1.MirrorPodAnnotationKey] != annotations["kubernetes.io/config.hash"] ||
		annotations["kubernetes.io/config.source"] != "file" {
		return false
	}
	owner := metav1.GetControllerOf(pod)
	if owner == nil || owner.Kind != "Node" || owner.APIVersion != "v1" || owner.Name != node.Name || owner.UID != node.UID {
		return false
	}
	if len(pod.Spec.Containers) == 0 {
		return false
	}
	for _, container := range pod.Spec.Containers {
		if !isGKEReleaseImage(container.Image) {
			return false
		}
	}
	if len(pod.Spec.Volumes) == 0 {
		return false
	}
	for _, volume := range pod.Spec.Volumes {
		if volume.HostPath == nil {
			return false
		}
		if _, allowed := gkeKubeProxyHostPaths[volume.Name]; !allowed {
			return false
		}
	}
	return true
}
