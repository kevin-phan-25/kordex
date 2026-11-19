package execution

import (
	"context"
	"fmt"
	"sort"

	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	authorizationv1client "k8s.io/client-go/kubernetes/typed/authorization/v1"
	"kordex.local/api/protocol"
)

// VerifyHostExecutionRBAC checks the effective permissions of the operator's
// own identity before it advertises the host executor to the hub. An unknown
// or denied review is reported as missing permission and therefore disables
// the executor. This is a capability hint; each real API request is still
// authorized by Kubernetes at execution time.
func VerifyHostExecutionRBAC(
	ctx context.Context,
	reviews authorizationv1client.SelfSubjectAccessReviewInterface,
	namespace, sshSecret, knownHostsConfigMap string,
) ([]string, error) {
	if reviews == nil {
		return nil, fmt.Errorf("host-execution authorization review client is unavailable")
	}
	if len(validation.IsDNS1123Label(namespace)) != 0 {
		return nil, fmt.Errorf("invalid host-execution RBAC probe namespace")
	}
	for _, name := range []string{sshSecret, knownHostsConfigMap} {
		if len(validation.IsDNS1123Subdomain(name)) != 0 {
			return nil, fmt.Errorf("invalid host-execution RBAC probe identity")
		}
	}
	checks := hostExecutionPermissions(namespace, sshSecret, knownHostsConfigMap)
	missing := make([]string, 0)
	for _, check := range checks {
		review, err := reviews.Create(ctx, &authorizationv1.SelfSubjectAccessReview{
			Spec: authorizationv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authorizationv1.ResourceAttributes{
				Namespace:   check.namespace,
				Verb:        check.verb,
				Group:       check.group,
				Resource:    check.resource,
				Subresource: check.subresource,
				Name:        check.name,
			}},
		}, metav1.CreateOptions{})
		if err != nil {
			return missing, fmt.Errorf("review host-execution permission %s: %w", check.label, err)
		}
		if !review.Status.Allowed || review.Status.Denied || review.Status.EvaluationError != "" {
			missing = append(missing, check.label)
		}
	}
	sort.Strings(missing)
	return missing, nil
}

// VerifyNodeMaintenanceRBAC checks the effective permissions required by the
// operator's ordinary worker drain and durable recovery path. A denied or
// indeterminate review disables the published capability; real requests are
// still independently authorized by Kubernetes.
func VerifyNodeMaintenanceRBAC(
	ctx context.Context,
	reviews authorizationv1client.SelfSubjectAccessReviewInterface,
	namespace string,
) ([]string, error) {
	if reviews == nil {
		return nil, fmt.Errorf("node-maintenance authorization review client is unavailable")
	}
	if len(validation.IsDNS1123Label(namespace)) != 0 {
		return nil, fmt.Errorf("invalid node-maintenance RBAC probe namespace")
	}
	missing := make([]string, 0)
	for _, check := range nodeMaintenancePermissions(namespace) {
		review, err := reviews.Create(ctx, &authorizationv1.SelfSubjectAccessReview{
			Spec: authorizationv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authorizationv1.ResourceAttributes{
				Namespace: check.namespace, Verb: check.verb, Group: check.group,
				Resource: check.resource, Subresource: check.subresource, Name: check.name,
			}},
		}, metav1.CreateOptions{})
		if err != nil {
			return missing, fmt.Errorf("review node-maintenance permission %s: %w", check.label, err)
		}
		if !review.Status.Allowed || review.Status.Denied || review.Status.EvaluationError != "" {
			missing = append(missing, check.label)
		}
	}
	sort.Strings(missing)
	return missing, nil
}

func nodeMaintenancePermissions(namespace string) []hostExecutionPermission {
	checks := make([]hostExecutionPermission, 0, 25)
	add := func(namespace, verb, group, resource, subresource, name string) {
		label := resource
		if group != "" {
			label = group + "/" + resource
		}
		if subresource != "" {
			label += "/" + subresource
		}
		label += "." + verb
		if name != "" {
			label += "[" + name + "]"
		}
		if namespace != "" {
			label += "@" + namespace
		}
		checks = append(checks, hostExecutionPermission{namespace: namespace, verb: verb, group: group, resource: resource, subresource: subresource, name: name, label: label})
	}
	for _, verb := range []string{"get", "list", "patch"} {
		add("", verb, "", "nodes", "", "")
	}
	for _, verb := range []string{"get", "list"} {
		add("", verb, "", "pods", "", "")
		for _, resource := range []string{"persistentvolumes", "services"} {
			add("", verb, "", resource, "", "")
		}
		for _, resource := range []string{"deployments", "replicasets", "daemonsets"} {
			add("", verb, "apps", resource, "", "")
		}
		add("", verb, "policy", "poddisruptionbudgets", "", "")
		add("", verb, "ceph.rook.io", "cephclusters", "", "")
		for _, resource := range []string{"nodes", "replicas", "volumes"} {
			add("", verb, "longhorn.io", resource, "", "")
		}
	}
	add("", "create", "", "pods", "eviction", "")
	add("", "get", "", "namespaces", "", "kube-system")
	for _, verb := range []string{"get", "list", "watch", "update", "patch"} {
		add(namespace, verb, "operations.kordex.local", "nodemaintenances", "", "")
	}
	for _, verb := range []string{"get", "update", "patch"} {
		add(namespace, verb, "operations.kordex.local", "nodemaintenances", "status", "")
	}
	for _, resource := range []string{"maintenancepolicies", "maintenancecampaigns"} {
		for _, verb := range []string{"get", "list", "watch"} {
			add(namespace, verb, "operations.kordex.local", resource, "", "")
		}
	}
	add(namespace, "get", "coordination.k8s.io", "leases", "", protocol.ConnectionLease)
	for _, verb := range []string{"get", "update"} {
		add(protocol.SlotNamespace, verb, "coordination.k8s.io", "leases", "", "kordex-maintenance-cluster-slot")
	}
	for _, verb := range []string{"get", "create"} {
		add(protocol.SlotNamespace, verb, "", "configmaps", "", "")
	}
	return checks
}

type hostExecutionPermission struct {
	namespace   string
	verb        string
	group       string
	resource    string
	subresource string
	name        string
	label       string
}

func hostExecutionPermissions(namespace, sshSecret, knownHostsConfigMap string) []hostExecutionPermission {
	checks := make([]hostExecutionPermission, 0, 25)
	add := func(ns, verb, group, resource, subresource, name string) {
		label := resource
		if group != "" {
			label = group + "/" + resource
		}
		if subresource != "" {
			label += "/" + subresource
		}
		label += "." + verb
		if name != "" {
			label += "[" + name + "]"
		}
		if ns != "" {
			label += "@" + ns
		}
		checks = append(checks, hostExecutionPermission{namespace: ns, verb: verb, group: group, resource: resource, subresource: subresource, name: name, label: label})
	}
	for _, verb := range []string{"get", "list", "create", "delete"} {
		add(namespace, verb, "networking.k8s.io", "networkpolicies", "", "")
	}
	add(namespace, "get", "", "secrets", "", sshSecret)
	add(namespace, "get", "", "configmaps", "", knownHostsConfigMap)
	for _, verb := range []string{"get", "create"} {
		add(namespace, verb, "", "configmaps", "", "")
		add(protocol.SlotNamespace, verb, "", "configmaps", "", "")
	}
	for _, verb := range []string{"get", "update"} {
		add(protocol.SlotNamespace, verb, "coordination.k8s.io", "leases", "", "kordex-maintenance-cluster-slot")
	}
	for _, verb := range []string{"get", "list", "watch", "create", "update", "delete"} {
		add(namespace, verb, "batch", "jobs", "", "")
	}
	for _, verb := range []string{"get", "list"} {
		add(namespace, verb, "", "pods", "", "")
	}
	add(namespace, "get", "", "pods", "log", "")
	return checks
}
