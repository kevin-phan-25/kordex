package execution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"kordex.local/api/protocol"
)

const (
	EEPhasePreflight   = "preflight"
	EEPhaseApply       = "apply"
	eeJobLabel         = "operations.kordex.local/ee-job"
	eeOperationLabel   = "operations.kordex.local/operation-id"
	eePhaseLabel       = "operations.kordex.local/ee-phase"
	eeDigestAnnotation = "operations.kordex.local/plan-digest"
	eeReceiptPrefix    = "KORDEX_EE_RECEIPT="
)

var (
	ErrExecutionNotFound  = errors.New("Ansible EE job not found")
	ErrExecutionIdentity  = errors.New("Ansible EE resource identity mismatch")
	ErrExecutionReceipt   = errors.New("Ansible EE completion receipt missing or invalid")
	ErrExecutionCancelled = errors.New("Ansible EE operation has a durable cancellation tombstone")
)

// AnsibleJobExecutor launches a fixed Kordex entrypoint inside the EE image.
// Job and request names are deterministic, so retries observe existing work
// instead of submitting a second upgrade. It is intentionally not wired into
// the maintenance reconciler until VM recovery qualification is complete.
type AnsibleJobExecutor struct {
	Client              kubernetes.Interface
	Namespace           string
	ServiceAccount      string
	SSHUser             string
	SSHCredentialSecret string
	KnownHostsConfigMap string
	ImagePullSecrets    []string
}

type AnsibleJobRequest struct {
	OperationID string
	OwnerName   string
	OwnerUID    types.UID
	NodeName    string
	NodeUID     string
	Address     string
	MachineID   string
	BootID      string
	PlanDigest  string
	Phase       string
	Policy      protocol.UpgradePolicy
}

type AnsibleReceipt struct {
	OperationID  string            `json:"operationId"`
	PlanDigest   string            `json:"planDigest"`
	NodeUID      string            `json:"nodeUid"`
	MachineID    string            `json:"machineId"`
	BootIDBefore string            `json:"bootIdBefore"`
	BootIDAfter  string            `json:"bootIdAfter"`
	OSFamily     string            `json:"osFamily"`
	Rebooted     bool              `json:"rebooted"`
	Packages     map[string]string `json:"packages,omitempty"`
	CompletedAt  time.Time         `json:"completedAt"`
}

type AnsibleJobObservation struct {
	Name       string
	Phase      string
	Outcome    string
	Reason     string
	Receipt    *AnsibleReceipt
	ObservedAt time.Time
}

type eeRequestFile struct {
	OperationID string                 `json:"operationId"`
	Phase       string                 `json:"phase"`
	PlanDigest  string                 `json:"planDigest"`
	Node        eeNode                 `json:"node"`
	Policy      protocol.UpgradePolicy `json:"policy"`
}

type eeNode struct {
	Name      string `json:"name"`
	UID       string `json:"uid"`
	Address   string `json:"address"`
	MachineID string `json:"machineId,omitempty"`
	BootID    string `json:"bootId,omitempty"`
}

func (e *AnsibleJobExecutor) Validate() error {
	if e.Client == nil || !validDNSName(e.Namespace) || !validDNSName(e.ServiceAccount) || !validSSHUser(e.SSHUser) || !validDNSName(e.SSHCredentialSecret) || !validDNSName(e.KnownHostsConfigMap) {
		return errors.New("Ansible EE executor requires Kubernetes clients and fixed namespace, service account, SSH secret, and known-hosts ConfigMap")
	}
	if e.ServiceAccount != "kordex-upgrade-runner" {
		return errors.New("Ansible EE jobs must use the tokenless kordex-upgrade-runner service account")
	}
	for _, name := range e.ImagePullSecrets {
		if !validDNSName(name) {
			return errors.New("invalid Ansible EE image pull secret name")
		}
	}
	return nil
}

// Ensure creates the immutable request and one-shot Job, or verifies that an
// existing pair belongs to the exact operation, phase, target, and plan.
func (e *AnsibleJobExecutor) Ensure(ctx context.Context, request AnsibleJobRequest) (string, error) {
	if err := e.Validate(); err != nil {
		return "", err
	}
	if err := validateEERequest(request); err != nil {
		return "", err
	}
	jobName := eeJobName(request.OperationID, request.Phase)
	if cancelled, err := e.cancellationTombstone(ctx, request, jobName); err != nil {
		return "", err
	} else if cancelled {
		return "", ErrExecutionCancelled
	}
	requestData, err := json.Marshal(eeRequestFile{
		OperationID: request.OperationID,
		Phase:       request.Phase,
		PlanDigest:  request.PlanDigest,
		Node:        eeNode{Name: request.NodeName, UID: request.NodeUID, Address: canonicalIP(request.Address), MachineID: request.MachineID, BootID: request.BootID},
		Policy:      request.Policy,
	})
	if err != nil {
		return "", fmt.Errorf("encode Ansible EE request: %w", err)
	}
	if err = e.ensureRequestConfigMap(ctx, request, jobName, requestData); err != nil {
		return "", err
	}
	job := e.job(request, jobName)
	actual, err := e.Client.BatchV1().Jobs(e.Namespace).Create(ctx, job, metav1.CreateOptions{})
	if err == nil {
		if cancelled, tombstoneErr := e.cancellationTombstone(ctx, request, jobName); tombstoneErr != nil {
			return "", tombstoneErr
		} else if cancelled {
			if deleteErr := e.deleteOwnedJob(ctx, request, jobName); deleteErr != nil {
				return "", deleteErr
			}
			return "", ErrExecutionCancelled
		}
		return actual.Name, nil
	}
	if !apierrors.IsAlreadyExists(err) {
		// A timed-out create can have reached the API server. Reconcile by the
		// deterministic name before returning; never generate a replacement ID.
		actual, getErr := e.Client.BatchV1().Jobs(e.Namespace).Get(ctx, jobName, metav1.GetOptions{})
		if getErr != nil {
			return "", fmt.Errorf("create or resolve Ansible EE job: %w", err)
		}
		if identityErr := verifyEEJobIdentity(actual, request); identityErr != nil {
			return "", identityErr
		}
		if cancelled, tombstoneErr := e.cancellationTombstone(ctx, request, jobName); tombstoneErr != nil {
			return "", tombstoneErr
		} else if cancelled {
			if deleteErr := e.deleteOwnedJob(ctx, request, jobName); deleteErr != nil {
				return "", deleteErr
			}
			return "", ErrExecutionCancelled
		}
		return actual.Name, nil
	}
	actual, err = e.Client.BatchV1().Jobs(e.Namespace).Get(ctx, jobName, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("read existing Ansible EE job: %w", err)
	}
	if err = verifyEEJobIdentity(actual, request); err != nil {
		return "", err
	}
	if cancelled, tombstoneErr := e.cancellationTombstone(ctx, request, jobName); tombstoneErr != nil {
		return "", tombstoneErr
	} else if cancelled {
		if deleteErr := e.deleteOwnedJob(ctx, request, jobName); deleteErr != nil {
			return "", deleteErr
		}
		return "", ErrExecutionCancelled
	}
	return actual.Name, nil
}

func (e *AnsibleJobExecutor) Observe(ctx context.Context, request AnsibleJobRequest, reference string) (AnsibleJobObservation, error) {
	if err := e.Validate(); err != nil {
		return AnsibleJobObservation{}, err
	}
	if err := validateEERequest(request); err != nil {
		return AnsibleJobObservation{}, err
	}
	expected := eeJobName(request.OperationID, request.Phase)
	if reference != expected {
		return AnsibleJobObservation{}, ErrExecutionIdentity
	}
	if cancelled, tombstoneErr := e.cancellationTombstone(ctx, request, reference); tombstoneErr != nil {
		return AnsibleJobObservation{}, tombstoneErr
	} else if cancelled {
		return AnsibleJobObservation{Name: reference, Phase: "RecoveryRequired", Outcome: "Ambiguous", Reason: "CancellationRequested", ObservedAt: time.Now().UTC()}, nil
	}
	job, err := e.Client.BatchV1().Jobs(e.Namespace).Get(ctx, reference, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return AnsibleJobObservation{}, ErrExecutionNotFound
	}
	if err != nil {
		return AnsibleJobObservation{}, err
	}
	if err = verifyEEJobIdentity(job, request); err != nil {
		return AnsibleJobObservation{}, err
	}
	observation := AnsibleJobObservation{Name: job.Name, Phase: "Running", ObservedAt: time.Now().UTC()}
	if job.Status.Succeeded > 0 {
		observation.Phase = "Succeeded"
		receipt, receiptErr := e.readReceipt(ctx, job, request)
		if receiptErr != nil {
			observation.Phase = "RecoveryRequired"
			observation.Outcome = "Ambiguous"
			observation.Reason = "ReceiptUnavailable"
			return observation, receiptErr
		}
		observation.Outcome = "Succeeded"
		observation.Receipt = receipt
		return observation, nil
	}
	if job.Status.Failed > 0 {
		observation.Phase = "RecoveryRequired"
		observation.Outcome = "Ambiguous"
		observation.Reason = "ExecutionJobFailed"
		for _, condition := range job.Status.Conditions {
			if condition.Type == batchv1.JobFailed && condition.Status == corev1.ConditionTrue {
				observation.Reason = safeReason(condition.Reason, "ExecutionJobFailed")
				break
			}
		}
	}
	return observation, nil
}

// Cancel requests Kubernetes Job deletion but does not claim the remote host
// stopped. The caller must verify node/workload recovery because SSH loss can
// occur after apt or reboot was already issued.
func (e *AnsibleJobExecutor) Cancel(ctx context.Context, request AnsibleJobRequest, reference string) error {
	if err := e.Validate(); err != nil {
		return err
	}
	if err := validateEERequest(request); err != nil {
		return err
	}
	if reference != eeJobName(request.OperationID, request.Phase) {
		return ErrExecutionIdentity
	}
	if err := e.createCancellationTombstone(ctx, request, reference); err != nil {
		return err
	}
	return e.deleteOwnedJob(ctx, request, reference)
}

func (e *AnsibleJobExecutor) createCancellationTombstone(ctx context.Context, request AnsibleJobRequest, jobName string) error {
	immutable := true
	controller := true
	blockOwnerDeletion := false
	tombstone := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   e.Namespace,
			Name:        jobName + "-cancelled",
			Labels:      eeLabels(request),
			Annotations: map[string]string{eeDigestAnnotation: request.PlanDigest},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: protocol.OperationGroup + "/" + protocol.OperationVersion,
				Kind:       "NodeMaintenance", Name: request.OwnerName, UID: request.OwnerUID,
				Controller: &controller, BlockOwnerDeletion: &blockOwnerDeletion,
			}},
		},
		Immutable: &immutable,
		Data: map[string]string{
			"operationId": request.OperationID,
			"phase":       request.Phase,
			"planDigest":  request.PlanDigest,
		},
	}
	_, err := e.Client.CoreV1().ConfigMaps(e.Namespace).Create(ctx, tombstone, metav1.CreateOptions{})
	if err == nil {
		return nil
	}
	actual, getErr := e.Client.CoreV1().ConfigMaps(e.Namespace).Get(ctx, tombstone.Name, metav1.GetOptions{})
	if getErr != nil {
		return fmt.Errorf("create or resolve Ansible EE cancellation tombstone: %w", err)
	}
	if actual.Immutable == nil || !*actual.Immutable || actual.Data["operationId"] != request.OperationID || actual.Data["phase"] != request.Phase || actual.Data["planDigest"] != request.PlanDigest || actual.Annotations[eeDigestAnnotation] != request.PlanDigest || !hasOwnerUID(actual.OwnerReferences, request.OwnerUID) {
		return ErrExecutionIdentity
	}
	return nil
}

func (e *AnsibleJobExecutor) cancellationTombstone(ctx context.Context, request AnsibleJobRequest, jobName string) (bool, error) {
	tombstone, err := e.Client.CoreV1().ConfigMaps(e.Namespace).Get(ctx, jobName+"-cancelled", metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if tombstone.Immutable == nil || !*tombstone.Immutable || tombstone.Data["operationId"] != request.OperationID || tombstone.Data["phase"] != request.Phase || tombstone.Data["planDigest"] != request.PlanDigest || tombstone.Annotations[eeDigestAnnotation] != request.PlanDigest || !hasOwnerUID(tombstone.OwnerReferences, request.OwnerUID) {
		return false, ErrExecutionIdentity
	}
	return true, nil
}

func (e *AnsibleJobExecutor) deleteOwnedJob(ctx context.Context, request AnsibleJobRequest, jobName string) error {
	job, err := e.Client.BatchV1().Jobs(e.Namespace).Get(ctx, jobName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if err = verifyEEJobIdentity(job, request); err != nil {
		return err
	}
	propagation := metav1.DeletePropagationForeground
	err = e.Client.BatchV1().Jobs(e.Namespace).Delete(ctx, jobName, metav1.DeleteOptions{PropagationPolicy: &propagation})
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}

func validateEERequest(request AnsibleJobRequest) error {
	if !protocol.ValidUUID(request.OperationID) || request.OwnerName != "op-"+request.OperationID || request.OwnerUID == "" || request.NodeName == "" || request.NodeUID == "" || !protocol.ValidSHA256Digest(request.PlanDigest) {
		return errors.New("invalid Ansible EE operation or target identity")
	}
	if request.Phase != EEPhasePreflight && request.Phase != EEPhaseApply {
		return errors.New("unsupported Ansible EE job phase")
	}
	if net.ParseIP(request.Address) == nil {
		return errors.New("Ansible EE target address must be an IP address")
	}
	if err := request.Policy.Validate(); err != nil {
		return fmt.Errorf("invalid Ansible EE policy: %w", err)
	}
	digest, err := request.Policy.Digest()
	if err != nil || digest != request.PlanDigest {
		return errors.New("Ansible EE policy digest does not match signed operation")
	}
	if request.Policy.OSFamily != "debian" || request.Policy.PlaybookCatalogID != "kordex.os-upgrade.debian.v1" {
		return errors.New("this Ansible EE executor currently supports the Debian playbook catalog only")
	}
	if len(request.Policy.PreHooks) != 0 || len(request.Policy.PostHooks) != 0 {
		return errors.New("the initial Ansible EE catalog does not support pre or post hooks")
	}
	if request.Phase == EEPhasePreflight && (request.MachineID != "" || request.BootID != "") {
		return errors.New("preflight must discover host machine and boot identity")
	}
	if request.Phase == EEPhaseApply && (!validMachineID(request.MachineID) || !protocol.ValidUUID(request.BootID)) {
		return errors.New("apply requires preflighted machine and boot identity")
	}
	return nil
}

func (e *AnsibleJobExecutor) ensureRequestConfigMap(ctx context.Context, request AnsibleJobRequest, jobName string, data []byte) error {
	immutable := true
	controller := true
	blockOwnerDeletion := false
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   e.Namespace,
			Name:        jobName + "-request",
			Labels:      eeLabels(request),
			Annotations: map[string]string{eeDigestAnnotation: request.PlanDigest},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: protocol.OperationGroup + "/" + protocol.OperationVersion,
				Kind:       "NodeMaintenance", Name: request.OwnerName, UID: request.OwnerUID,
				Controller: &controller, BlockOwnerDeletion: &blockOwnerDeletion,
			}},
		},
		Immutable: &immutable,
		Data:      map[string]string{"request.json": string(data)},
	}
	_, err := e.Client.CoreV1().ConfigMaps(e.Namespace).Create(ctx, cm, metav1.CreateOptions{})
	if err == nil {
		return nil
	}
	actual, getErr := e.Client.CoreV1().ConfigMaps(e.Namespace).Get(ctx, cm.Name, metav1.GetOptions{})
	if getErr != nil {
		return fmt.Errorf("create or resolve immutable Ansible EE request: %w", err)
	}
	if actual.Immutable == nil || !*actual.Immutable || actual.Data["request.json"] != string(data) || actual.Annotations[eeDigestAnnotation] != request.PlanDigest || !hasOwnerUID(actual.OwnerReferences, request.OwnerUID) {
		return ErrExecutionIdentity
	}
	return nil
}

func (e *AnsibleJobExecutor) job(request AnsibleJobRequest, name string) *batchv1.Job {
	deadline := int64((request.Policy.ExecutionTimeout + request.Policy.RebootTimeout + request.Policy.VerificationTimeout).Seconds())
	backoff := int32(0)
	completions, parallelism := int32(1), int32(1)
	trueValue, falseValue := true, false
	owner := metav1.OwnerReference{APIVersion: protocol.OperationGroup + "/" + protocol.OperationVersion, Kind: "NodeMaintenance", Name: request.OwnerName, UID: request.OwnerUID, Controller: &trueValue, BlockOwnerDeletion: &falseValue}
	imagePullSecrets := make([]corev1.LocalObjectReference, 0, len(e.ImagePullSecrets))
	for _, secret := range e.ImagePullSecrets {
		imagePullSecrets = append(imagePullSecrets, corev1.LocalObjectReference{Name: secret})
	}
	labelsForJob := eeLabels(request)
	labelsForJob[eeJobLabel] = name
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: e.Namespace, Name: name, Labels: labelsForJob,
			Annotations:     map[string]string{eeDigestAnnotation: request.PlanDigest},
			OwnerReferences: []metav1.OwnerReference{owner},
		},
		Spec: batchv1.JobSpec{
			BackoffLimit: &backoff, Completions: &completions, Parallelism: &parallelism,
			ActiveDeadlineSeconds: &deadline,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labelsForJob, Annotations: map[string]string{eeDigestAnnotation: request.PlanDigest}},
				Spec: corev1.PodSpec{
					RestartPolicy:                 corev1.RestartPolicyNever,
					TerminationGracePeriodSeconds: int64ptr(30),
					ServiceAccountName:            e.ServiceAccount,
					AutomountServiceAccountToken:  &falseValue,
					ImagePullSecrets:              imagePullSecrets,
					SecurityContext:               &corev1.PodSecurityContext{RunAsNonRoot: &trueValue, RunAsUser: int64ptr(1000), RunAsGroup: int64ptr(1000), FSGroup: int64ptr(1000), SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}},
					Containers: []corev1.Container{{
						Name: "ansible-ee", Image: request.Policy.ExecutionEnvironment, ImagePullPolicy: corev1.PullIfNotPresent,
						Command: []string{"/usr/local/bin/kordex-upgrade"}, Args: []string{"--request=/etc/kordex/request.json", "--result=/var/run/kordex/result.json"},
						Env: []corev1.EnvVar{
							{Name: "KORDEX_ANSIBLE_USER", Value: e.SSHUser},
							{Name: "HOME", Value: "/var/run/kordex/home"},
							{Name: "ANSIBLE_HOME", Value: "/var/run/kordex/ansible"},
							{Name: "ANSIBLE_LOCAL_TEMP", Value: "/var/run/kordex/tmp"},
						},
						SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: &falseValue, ReadOnlyRootFilesystem: &trueValue, Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}},
						VolumeMounts:    []corev1.VolumeMount{{Name: "request", MountPath: "/etc/kordex", ReadOnly: true}, {Name: "ssh-credentials", MountPath: "/run/kordex/ssh", ReadOnly: true}, {Name: "known-hosts", MountPath: "/run/kordex/known-hosts", ReadOnly: true}, {Name: "work", MountPath: "/var/run/kordex"}},
						Resources:       corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resourceQuantity("100m"), corev1.ResourceMemory: resourceQuantity("128Mi")}, Limits: corev1.ResourceList{corev1.ResourceCPU: resourceQuantity("2"), corev1.ResourceMemory: resourceQuantity("2Gi")}},
					}},
					Volumes: []corev1.Volume{
						{Name: "request", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: name + "-request"}, DefaultMode: int32ptr(0440)}}},
						{Name: "ssh-credentials", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: e.SSHCredentialSecret, DefaultMode: int32ptr(0440), Items: []corev1.KeyToPath{{Key: "id_ed25519", Path: "id_ed25519"}}}}},
						{Name: "known-hosts", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: e.KnownHostsConfigMap}, DefaultMode: int32ptr(0444), Items: []corev1.KeyToPath{{Key: "known_hosts", Path: "known_hosts"}}}}},
						{Name: "work", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{SizeLimit: resourceQuantityPtr("128Mi")}}},
					},
				},
			},
		},
	}
}

func (e *AnsibleJobExecutor) readReceipt(ctx context.Context, job *batchv1.Job, request AnsibleJobRequest) (*AnsibleReceipt, error) {
	selector := labels.Set{eeJobLabel: job.Name}.AsSelector().String()
	pods, err := e.Client.CoreV1().Pods(e.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return nil, err
	}
	var completed *corev1.Pod
	for i := range pods.Items {
		if pods.Items[i].Status.Phase == corev1.PodSucceeded {
			if completed != nil {
				return nil, ErrExecutionReceipt
			}
			completed = &pods.Items[i]
		}
	}
	if completed == nil {
		return nil, ErrExecutionReceipt
	}
	limit := int64(1 << 20)
	data, err := e.Client.CoreV1().Pods(e.Namespace).GetLogs(completed.Name, &corev1.PodLogOptions{Container: "ansible-ee", LimitBytes: &limit}).Do(ctx).Raw()
	if err != nil {
		return nil, err
	}
	var receipt *AnsibleReceipt
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, eeReceiptPrefix) {
			continue
		}
		var candidate AnsibleReceipt
		if json.Unmarshal([]byte(strings.TrimPrefix(line, eeReceiptPrefix)), &candidate) != nil {
			return nil, ErrExecutionReceipt
		}
		if receipt != nil {
			return nil, ErrExecutionReceipt
		}
		receipt = &candidate
	}
	createdAt := job.CreationTimestamp.Time
	if receipt == nil || receipt.OperationID != request.OperationID || receipt.PlanDigest != request.PlanDigest || receipt.NodeUID != request.NodeUID || !validMachineID(receipt.MachineID) || !protocol.ValidUUID(receipt.BootIDBefore) || !protocol.ValidUUID(receipt.BootIDAfter) || receipt.OSFamily != request.Policy.OSFamily || receipt.CompletedAt.IsZero() || receipt.CompletedAt.Before(createdAt.Add(-time.Second)) || receipt.CompletedAt.After(time.Now().Add(5*time.Second)) {
		return nil, ErrExecutionReceipt
	}
	if request.Phase == EEPhasePreflight {
		if len(receipt.Packages) != 0 || receipt.Rebooted || receipt.BootIDBefore != receipt.BootIDAfter {
			return nil, ErrExecutionReceipt
		}
	} else {
		if receipt.MachineID != request.MachineID || receipt.BootIDBefore != request.BootID {
			return nil, ErrExecutionReceipt
		}
		if request.Policy.Reboot == protocol.RebootRequired && !receipt.Rebooted || request.Policy.Reboot == protocol.RebootNever && receipt.Rebooted {
			return nil, ErrExecutionReceipt
		}
		if receipt.Rebooted != (receipt.BootIDBefore != receipt.BootIDAfter) {
			return nil, ErrExecutionReceipt
		}
		if len(receipt.Packages) != len(request.Policy.Packages) {
			return nil, ErrExecutionReceipt
		}
		for _, item := range request.Policy.Packages {
			if receipt.Packages[item.Name] != item.Version {
				return nil, ErrExecutionReceipt
			}
		}
	}
	return receipt, nil
}

func verifyEEJobIdentity(job *batchv1.Job, request AnsibleJobRequest) error {
	if job.Name != eeJobName(request.OperationID, request.Phase) || job.Labels[eeOperationLabel] != request.OperationID || job.Labels[eePhaseLabel] != request.Phase || job.Annotations[eeDigestAnnotation] != request.PlanDigest || !hasOwnerUID(job.OwnerReferences, request.OwnerUID) {
		return ErrExecutionIdentity
	}
	if len(job.Spec.Template.Spec.Containers) != 1 || job.Spec.Template.Spec.Containers[0].Name != "ansible-ee" || job.Spec.Template.Spec.Containers[0].Image != request.Policy.ExecutionEnvironment || strings.Join(job.Spec.Template.Spec.Containers[0].Command, " ") != "/usr/local/bin/kordex-upgrade" || strings.Join(job.Spec.Template.Spec.Containers[0].Args, " ") != "--request=/etc/kordex/request.json --result=/var/run/kordex/result.json" {
		return ErrExecutionIdentity
	}
	if job.Spec.Template.Spec.ServiceAccountName != "kordex-upgrade-runner" || job.Spec.Template.Spec.AutomountServiceAccountToken == nil || *job.Spec.Template.Spec.AutomountServiceAccountToken || job.Spec.Template.Spec.RestartPolicy != corev1.RestartPolicyNever || job.Spec.BackoffLimit == nil || *job.Spec.BackoffLimit != 0 {
		return ErrExecutionIdentity
	}
	return nil
}

func eeLabels(request AnsibleJobRequest) map[string]string {
	return map[string]string{eeOperationLabel: request.OperationID, eePhaseLabel: request.Phase}
}

func eeJobName(operationID, phase string) string {
	return "kordex-ee-" + strings.ReplaceAll(operationID, "-", "") + "-" + phase
}

func hasOwnerUID(refs []metav1.OwnerReference, uid types.UID) bool {
	for _, ref := range refs {
		if ref.UID == uid {
			return true
		}
	}
	return false
}

func safeReason(reason, fallback string) string {
	if reason == "" || len(reason) > 128 {
		return fallback
	}
	for _, r := range reason {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
			return fallback
		}
	}
	return reason
}

func validDNSName(value string) bool {
	if len(value) == 0 || len(value) > 253 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

func validSSHUser(value string) bool {
	if len(value) == 0 || len(value) > 32 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}

func canonicalIP(value string) string { return net.ParseIP(value).String() }
func int64ptr(value int64) *int64     { return &value }
func int32ptr(value int32) *int32     { return &value }

func validMachineID(value string) bool {
	if len(value) != 32 {
		return false
	}
	for _, r := range value {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') {
			return false
		}
	}
	return true
}

func resourceQuantity(value string) resource.Quantity { return resource.MustParse(value) }
func resourceQuantityPtr(value string) *resource.Quantity {
	quantity := resource.MustParse(value)
	return &quantity
}
