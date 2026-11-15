package inventory

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"kordex.local/api/protocol"
)

type Collector struct{ Client kubernetes.Interface }

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
			item := protocol.Node{Labels: completeLabels, UID: string(node.UID), Name: node.Name, OSImage: info.OSImage, KernelVersion: info.KernelVersion, KubeletVersion: info.KubeletVersion, Architecture: info.Architecture, ContainerRuntime: info.ContainerRuntimeVersion, Unschedulable: node.Spec.Unschedulable, ControlPlane: cp || master, Zone: node.Labels["topology.kubernetes.io/zone"]}
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
	return report, nil
}
