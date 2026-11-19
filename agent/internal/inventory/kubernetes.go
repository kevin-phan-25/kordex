package inventory

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	coordinationclient "k8s.io/client-go/kubernetes/typed/coordination/v1"
	metadataclient "k8s.io/client-go/metadata"

	"kordex.local/api/lifecycle"
	operations "kordex.local/api/operations/v1alpha1"
	"kordex.local/api/protocol"
)

var MaintenancePoliciesGVR = schema.GroupVersionResource{Group: protocol.OperationGroup, Version: protocol.OperationVersion, Resource: "maintenancepolicies"}

type Collector struct {
	Client        kubernetes.Interface
	Metadata      metadataclient.Interface
	Namespace     string
	PolicyReader  dynamic.ResourceInterface
	OperatorLease coordinationclient.LeaseInterface
	Logger        *slog.Logger
}

func (c Collector) ClusterUID(ctx context.Context) (string, error) {
	ns, err := c.Client.CoreV1().Namespaces().Get(ctx, "kube-system", metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	if ns.UID == "" {
		return "", fmt.Errorf("kube-system namespace has no UID")
	}
	return string(ns.UID), nil
}
func (c Collector) Collect(ctx context.Context) (protocol.Report, error) {
	report := protocol.Report{ObservedAt: time.Now().UTC(), Nodes: []protocol.Node{}}
	uid, err := c.ClusterUID(ctx)
	if err != nil {
		return report, err
	}
	report.ClusterUID = uid
	version, err := c.Client.Discovery().ServerVersion()
	if err != nil {
		return report, err
	}
	report.KubernetesVersion = version.GitVersion
	capabilities := c.collectClusterCapabilities(ctx)
	report.ClusterCapabilities = &capabilities
	continuation := ""
	for {
		list, err := c.Client.CoreV1().Nodes().List(ctx, metav1.ListOptions{Limit: 500, Continue: continuation})
		if err != nil {
			return report, err
		}
		for _, node := range list.Items {
			info := node.Status.NodeInfo
			_, cp := node.Labels["node-role.kubernetes.io/control-plane"]
			_, master := node.Labels["node-role.kubernetes.io/master"]
			completeLabels := map[string]string{}
			for key, value := range node.Labels {
				completeLabels[key] = value
			}
			if !protocol.ValidNodeLabels(completeLabels) {
				return report, fmt.Errorf("node labels exceed supported evidence bounds")
			}
			item := protocol.Node{Labels: completeLabels, UID: string(node.UID), Name: node.Name, OSImage: info.OSImage, KernelVersion: info.KernelVersion, KubeletVersion: info.KubeletVersion, Architecture: info.Architecture, ContainerRuntime: info.ContainerRuntimeVersion, ProviderID: node.Spec.ProviderID, Unschedulable: node.Spec.Unschedulable, ControlPlane: cp || master, Zone: node.Labels["topology.kubernetes.io/zone"]}
			discovery := lifecycle.DiscoverKubernetes(info.KubeletVersion, info.ContainerRuntimeVersion, node.Spec.ProviderID, completeLabels, cp || master)
			item.Lifecycle = &discovery
			for _, condition := range node.Status.Conditions {
				if condition.Type == corev1.NodeReady {
					item.Ready = condition.Status == corev1.ConditionTrue
				}
			}
			report.Nodes = append(report.Nodes, item)
			if len(report.Nodes) > protocol.MaxNodes {
				return report, fmt.Errorf("cluster exceeds supported inventory bound")
			}
		}
		continuation = list.Continue
		if continuation == "" {
			break
		}
	}
	if c.PolicyReader != nil {
		catalog, err := c.collectPolicyCatalog(ctx)
		if err != nil {
			if c.Logger != nil {
				c.Logger.WarnContext(ctx, "maintenance policy catalog unavailable", "error", err.Error())
			}
		} else {
			if c.OperatorLease != nil {
				lease, leaseErr := c.OperatorLease.Get(ctx, "kordex-operator-capabilities", metav1.GetOptions{})
				if leaseErr == nil && lease.Spec.HolderIdentity != nil && *lease.Spec.HolderIdentity == "kordex-operator" && lease.Spec.RenewTime != nil && lease.Spec.LeaseDurationSeconds != nil && *lease.Spec.LeaseDurationSeconds == int32(protocol.OperatorCapabilityLifetime/time.Second) {
					observed := lease.Spec.RenewTime.Time.UTC()
					if time.Since(observed) >= 0 && time.Since(observed) <= time.Duration(*lease.Spec.LeaseDurationSeconds)*time.Second {
						catalog.Capabilities = &protocol.OperatorCapabilities{
							ObservedAt:         observed,
							NodeMaintenance:    lease.Annotations["operations.kordex.local/node-maintenance"] == "true",
							HostUpgrades:       lease.Annotations["operations.kordex.local/host-upgrades"] == "true",
							GKENodePoolUpgrade: lease.Annotations["operations.kordex.local/gke-node-pool-upgrade"] == "true",
						}
					}
				} else if leaseErr != nil && !apierrors.IsNotFound(leaseErr) && c.Logger != nil {
					c.Logger.WarnContext(ctx, "operator capability lease unavailable", "error", leaseErr.Error())
				}
			}
			report.PolicyCatalog = catalog
		}
	}
	return report, nil
}

func (c Collector) collectClusterCapabilities(ctx context.Context) protocol.ClusterCapabilities {
	namespace := c.Namespace
	if namespace == "" {
		namespace = "kordex-system"
	}
	return protocol.ClusterCapabilities{
		ObservedAt:                 time.Now().UTC(),
		CNIHints:                   c.collectCNIHints(ctx),
		CSIDrivers:                 c.collectCSIDrivers(ctx),
		StorageProvisioners:        c.collectStorageProvisioners(ctx),
		AdmissionAPIs:              c.collectAdmissionConfiguration(ctx),
		PodSecurityNamespaceLabels: c.collectPodSecurityLabels(ctx, namespace),
	}
}

func (c Collector) collectCNIHints(ctx context.Context) protocol.CapabilityObservation {
	const source = "kube-system-daemonset-name-hints"
	known := map[string]string{
		"antrea-agent":    "antrea",
		"aws-node":        "aws-vpc-cni",
		"calico-node":     "calico",
		"cilium":          "cilium",
		"cilium-agent":    "cilium",
		"kube-flannel-ds": "flannel",
		"kube-flannel":    "flannel",
		"weave-net":       "weave",
	}
	values := map[string]struct{}{}
	continuation := ""
	count := 0
	for {
		list, err := c.Client.AppsV1().DaemonSets("kube-system").List(ctx, metav1.ListOptions{Limit: 500, Continue: continuation})
		if err != nil {
			return unknownCapability(source, capabilityReadError(err))
		}
		count += len(list.Items)
		if count > protocol.MaxClusterCapabilityObjects {
			return unknownCapability(source, "EvidenceLimitExceeded")
		}
		for _, item := range list.Items {
			if hint, ok := known[item.Name]; ok {
				values[hint] = struct{}{}
			}
		}
		continuation = list.Continue
		if continuation == "" {
			break
		}
	}
	if len(values) == 0 {
		return unknownCapability(source, "NoRecognizedHint")
	}
	return observedCapability(source, sortedSet(values))
}

func (c Collector) collectCSIDrivers(ctx context.Context) protocol.CapabilityObservation {
	const source = "CSINode.spec.drivers"
	values := map[string]struct{}{}
	continuation := ""
	count := 0
	for {
		list, err := c.Client.StorageV1().CSINodes().List(ctx, metav1.ListOptions{Limit: 500, Continue: continuation})
		if err != nil {
			return unknownCapability(source, capabilityReadError(err))
		}
		count += len(list.Items)
		if count > protocol.MaxClusterCapabilityObjects {
			return unknownCapability(source, "EvidenceLimitExceeded")
		}
		for _, item := range list.Items {
			for _, driver := range item.Spec.Drivers {
				if driver.Name == "" || len(driver.Name) > 253 {
					return unknownCapability(source, "QueryFailed")
				}
				values[driver.Name] = struct{}{}
				if len(values) > protocol.MaxCapabilityEvidenceValues {
					return unknownCapability(source, "EvidenceLimitExceeded")
				}
			}
		}
		continuation = list.Continue
		if continuation == "" {
			break
		}
	}
	return observedCapability(source, sortedSet(values))
}

func (c Collector) collectStorageProvisioners(ctx context.Context) protocol.CapabilityObservation {
	const source = "StorageClass.provisioner"
	values := map[string]struct{}{}
	continuation := ""
	count := 0
	for {
		list, err := c.Client.StorageV1().StorageClasses().List(ctx, metav1.ListOptions{Limit: 500, Continue: continuation})
		if err != nil {
			return unknownCapability(source, capabilityReadError(err))
		}
		count += len(list.Items)
		if count > protocol.MaxClusterCapabilityObjects {
			return unknownCapability(source, "EvidenceLimitExceeded")
		}
		for _, item := range list.Items {
			if item.Provisioner == "" || len(item.Provisioner) > 253 {
				return unknownCapability(source, "QueryFailed")
			}
			values[item.Provisioner] = struct{}{}
			if len(values) > protocol.MaxCapabilityEvidenceValues {
				return unknownCapability(source, "EvidenceLimitExceeded")
			}
		}
		continuation = list.Continue
		if continuation == "" {
			break
		}
	}
	return observedCapability(source, sortedSet(values))
}

func (c Collector) collectAdmissionConfiguration(ctx context.Context) protocol.CapabilityObservation {
	const source = "admissionregistration.k8s.io/v1 configuration counts"
	if c.Metadata == nil {
		return unknownCapability(source, "DiscoveryUnavailable")
	}
	resources, err := c.Client.Discovery().ServerResourcesForGroupVersion("admissionregistration.k8s.io/v1")
	if err != nil {
		if apierrors.IsForbidden(err) || apierrors.IsUnauthorized(err) {
			return unknownCapability(source, "PermissionDenied")
		}
		return unknownCapability(source, "DiscoveryUnavailable")
	}
	if resources == nil {
		return unknownCapability(source, "DiscoveryUnavailable")
	}
	served := map[string]bool{}
	for _, resource := range resources.APIResources {
		served[resource.Name] = true
	}
	resourcesToInspect := []struct {
		name     string
		resource schema.GroupVersionResource
	}{
		{"mutatingwebhookconfigurations", schema.GroupVersionResource{Group: "admissionregistration.k8s.io", Version: "v1", Resource: "mutatingwebhookconfigurations"}},
		{"validatingwebhookconfigurations", schema.GroupVersionResource{Group: "admissionregistration.k8s.io", Version: "v1", Resource: "validatingwebhookconfigurations"}},
		{"validatingadmissionpolicies", schema.GroupVersionResource{Group: "admissionregistration.k8s.io", Version: "v1", Resource: "validatingadmissionpolicies"}},
		{"validatingadmissionpolicybindings", schema.GroupVersionResource{Group: "admissionregistration.k8s.io", Version: "v1", Resource: "validatingadmissionpolicybindings"}},
	}
	values := make([]string, 0, len(resourcesToInspect))
	for _, resource := range resourcesToInspect {
		count := 0
		if served[resource.name] {
			continuation := ""
			for {
				page, err := c.Metadata.Resource(resource.resource).List(ctx, metav1.ListOptions{Limit: 500, Continue: continuation})
				if err != nil {
					return unknownCapability(source, capabilityReadError(err))
				}
				count += len(page.Items)
				if count > protocol.MaxClusterCapabilityObjects {
					return unknownCapability(source, "EvidenceLimitExceeded")
				}
				continuation = page.Continue
				if continuation == "" {
					break
				}
			}
			values = append(values, resource.name+"="+strconv.Itoa(count))
		} else {
			values = append(values, resource.name+"=unserved")
		}
	}
	slices.Sort(values)
	return observedCapability(source, values)
}

func (c Collector) collectPodSecurityLabels(ctx context.Context, namespace string) protocol.CapabilityObservation {
	const source = "agent-namespace Pod Security labels"
	item, err := c.Client.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	if err != nil {
		return unknownCapability(source, capabilityReadError(err))
	}
	values := map[string]struct{}{}
	for key, value := range item.Labels {
		if strings.HasPrefix(key, "pod-security.kubernetes.io/") {
			values[key+"="+value] = struct{}{}
		}
	}
	return observedCapability(source, sortedSet(values))
}

func capabilityReadError(err error) string {
	if apierrors.IsForbidden(err) || apierrors.IsUnauthorized(err) {
		return "PermissionDenied"
	}
	return "QueryFailed"
}

func unknownCapability(source, reason string) protocol.CapabilityObservation {
	return protocol.CapabilityObservation{State: "Unknown", Source: source, Values: []string{}, ReasonCode: reason}
}

func observedCapability(source string, values []string) protocol.CapabilityObservation {
	return protocol.CapabilityObservation{State: "Observed", Source: source, Values: values}
}

func sortedSet(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	slices.Sort(result)
	return result
}

func (c Collector) collectPolicyCatalog(ctx context.Context) (*protocol.MaintenancePolicyCatalog, error) {
	catalog := &protocol.MaintenancePolicyCatalog{ObservedAt: time.Now().UTC(), Items: []protocol.MaintenancePolicyCatalogEntry{}}
	continuation := ""
	for {
		list, err := c.PolicyReader.List(ctx, metav1.ListOptions{Limit: protocol.MaxPolicyCatalogItems + 1, Continue: continuation})
		if apierrors.IsNotFound(err) {
			// A missing CRD is an observed empty catalog, not an inventory failure.
			return catalog, nil
		}
		if err != nil {
			return nil, err
		}
		for i := range list.Items {
			if len(catalog.Items) >= protocol.MaxPolicyCatalogItems {
				return nil, fmt.Errorf("maintenance policy catalog exceeds supported bound")
			}
			entry, err := maintenancePolicyEntry(&list.Items[i])
			if err != nil {
				return nil, err
			}
			catalog.Items = append(catalog.Items, entry)
		}
		continuation = list.GetContinue()
		if continuation == "" {
			break
		}
	}
	return catalog, nil
}

func maintenancePolicyEntry(object *unstructured.Unstructured) (protocol.MaintenancePolicyCatalogEntry, error) {
	var entry protocol.MaintenancePolicyCatalogEntry
	if object.GetName() == "" || object.GetUID() == "" || object.GetGeneration() < 1 {
		return entry, fmt.Errorf("maintenance policy lacks immutable identity")
	}
	var spec operations.MaintenancePolicySpec
	specMap, found, err := unstructured.NestedMap(object.Object, "spec")
	if err != nil || !found {
		return entry, fmt.Errorf("maintenance policy spec unavailable")
	}
	if err = runtime.DefaultUnstructuredConverter.FromUnstructured(specMap, &spec); err != nil {
		return entry, fmt.Errorf("decode maintenance policy: %w", err)
	}
	entry.Policy = protocol.PolicyReference{Name: object.GetName(), UID: string(object.GetUID()), Generation: object.GetGeneration()}
	entry.NodeSelector = spec.NodeSelector
	if spec.ProtectedNodeSelector != nil {
		entry.ProtectedNodeSelector = spec.ProtectedNodeSelector.DeepCopy()
	}
	entry.AllowedActions = append([]string(nil), spec.AllowedActions...)
	entry.Suspended = spec.Suspended
	if spec.Upgrade != nil {
		digest, digestErr := spec.Upgrade.Digest()
		if digestErr != nil {
			entry.UpgradePlanInvalid = true
		} else {
			entry.Upgrade = spec.Upgrade
			entry.UpgradePlanDigest = digest
		}
	}
	if spec.ProviderUpgrade != nil {
		digest, digestErr := spec.ProviderUpgrade.Digest()
		if digestErr != nil {
			entry.ProviderPlanInvalid = true
		} else {
			entry.ProviderUpgrade = spec.ProviderUpgrade
			entry.ProviderPlanDigest = digest
		}
	}
	return entry, nil
}
