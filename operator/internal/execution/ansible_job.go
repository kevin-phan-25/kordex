package execution

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"

	"kordex.local/api/protocol"
)

const (
	EEPhasePreflight   = "preflight"
	EEPhaseApply       = "apply"
	EEPhaseReboot      = "reboot"
	EEPhaseInspect     = "inspect"
	eeJobLabel         = "operations.kordex.local/ee-job"
	eeOperationLabel   = "operations.kordex.local/operation-id"
	eePhaseLabel       = "operations.kordex.local/ee-phase"
	eeDigestAnnotation = "operations.kordex.local/plan-digest"
	eeTrustAnnotation  = "operations.kordex.local/recovery-trust-digest"
	eeTargetAnnotation = "operations.kordex.local/target-address"
	eeReceiptPrefix    = "KORDEX_EE_RECEIPT="
	eeErrorPrefix      = "KORDEX_EE_ERROR="
)

var (
	ErrExecutionNotFound  = errors.New("Ansible EE job not found")
	ErrExecutionIdentity  = errors.New("Ansible EE resource identity mismatch")
	ErrExecutionReceipt   = errors.New("Ansible EE completion receipt missing or invalid")
	ErrExecutionCancelled = errors.New("Ansible EE operation has a durable cancellation tombstone")
)

var executionEnvironmentDigest = regexp.MustCompile(`^[A-Za-z0-9.-]+(?::[0-9]+)?/[A-Za-z0-9._/-]+@sha256:[a-f0-9]{64}$`)

// AnsibleJobExecutor launches a fixed Kordex entrypoint inside the EE image.
// Job and request names are deterministic, so retries observe existing work
// instead of submitting a second upgrade. The maintenance reconciler uses it
// only when the explicit host-upgrade feature gate is enabled; VM qualification
// remains required before enabling it outside a disposable lab.
type AnsibleJobExecutor struct {
	Client    kubernetes.Interface
	Namespace string
	// LedgerNamespace holds immutable action receipts independently of the
	// NodeMaintenance object lifecycle. Receipt records intentionally have no
	// owner reference so deleting an acknowledged operation cannot erase the
	// evidence needed for recovery and audit.
	LedgerNamespace              string
	ServiceAccount               string
	SSHUser                      string
	SSHCredentialSecret          string
	KnownHostsConfigMap          string
	ImagePullSecrets             []string
	AllowedExecutionEnvironments []string
}

type AnsibleJobRequest struct {
	OperationID         string
	OwnerName           string
	OwnerUID            types.UID
	NodeName            string
	NodeUID             string
	Address             string
	MachineID           string
	BootID              string
	PlanDigest          string
	Phase               string
	RebootAuthorized    bool
	Policy              protocol.UpgradePolicy
	RecoveryAttempt     int32
	RecoveryTrustDigest string
	RecoveryRetryToken  string
}

type AnsibleReceipt struct {
	OperationID           string            `json:"operationId"`
	PlanDigest            string            `json:"planDigest"`
	NodeUID               string            `json:"nodeUid"`
	MachineID             string            `json:"machineId"`
	BootIDBefore          string            `json:"bootIdBefore"`
	BootIDAfter           string            `json:"bootIdAfter"`
	OSFamily              string            `json:"osFamily"`
	KernelVersion         string            `json:"kernelVersion"`
	ExpectedKernelVersion string            `json:"expectedKernelVersion,omitempty"`
	Rebooted              bool              `json:"rebooted"`
	RebootRequired        bool              `json:"rebootRequired,omitempty"`
	Packages              map[string]string `json:"packages,omitempty"`
	// BaselinePackages is optional read-only qualification evidence. Empty
	// versions mean the requested package was not installed at preflight.
	BaselinePackages map[string]string              `json:"baselinePackages,omitempty"`
	ActionMarker     *protocol.ActionMarkerEvidence `json:"actionMarker,omitempty"`
	CompletedAt      time.Time                      `json:"completedAt"`
}

type AnsibleJobObservation struct {
	Name             string
	Phase            string
	Outcome          string
	Reason           string
	Receipt          *AnsibleReceipt
	ReceiptReference string
	ReceiptDigest    string
	ObservedAt       time.Time
}

type eeRequestFile struct {
	OperationID      string                 `json:"operationId"`
	Phase            string                 `json:"phase"`
	PlanDigest       string                 `json:"planDigest"`
	RebootAuthorized bool                   `json:"rebootAuthorized,omitempty"`
	Node             eeNode                 `json:"node"`
	Policy           protocol.UpgradePolicy `json:"policy"`
}

type eeNode struct {
	Name      string `json:"name"`
	UID       string `json:"uid"`
	Address   string `json:"address"`
	MachineID string `json:"machineId,omitempty"`
	BootID    string `json:"bootId,omitempty"`
}

func (e *AnsibleJobExecutor) Validate() error {
	if e.Client == nil || !validDNSName(e.Namespace) || !validDNSName(e.ledgerNamespace()) || !validDNSName(e.ServiceAccount) || !validSSHUser(e.SSHUser) || !validDNSName(e.SSHCredentialSecret) || !validDNSName(e.KnownHostsConfigMap) {
		return errors.New("Ansible EE executor requires Kubernetes clients and fixed namespace, service account, SSH secret, and known-hosts ConfigMap")
	}
	if len(e.AllowedExecutionEnvironments) == 0 {
		return errors.New("Ansible EE executor requires an operator-configured execution environment digest allowlist")
	}
	allowed := make(map[string]struct{}, len(e.AllowedExecutionEnvironments))
	for _, image := range e.AllowedExecutionEnvironments {
		if !executionEnvironmentDigest.MatchString(image) {
			return errors.New("Ansible EE allowlist entries must be digest-pinned OCI image references")
		}
		if _, exists := allowed[image]; exists {
			return errors.New("Ansible EE execution environment allowlist contains a duplicate image")
		}
		allowed[image] = struct{}{}
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

func (e *AnsibleJobExecutor) ledgerNamespace() string {
	if e.LedgerNamespace == "" {
		return protocol.SlotNamespace
	}
	return e.LedgerNamespace
}

// RecoveryTrustDigest returns a digest of the operator-configured known-hosts
// data without exposing or logging the key material.
func (e *AnsibleJobExecutor) RecoveryTrustDigest(ctx context.Context) (string, error) {
	if err := e.Validate(); err != nil {
		return "", err
	}
	cm, err := e.Client.CoreV1().ConfigMaps(e.Namespace).Get(ctx, e.KnownHostsConfigMap, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	knownHosts := cm.Data["known_hosts"]
	if strings.TrimSpace(knownHosts) == "" {
		return "", errors.New("known-hosts ConfigMap has no known_hosts data")
	}
	secret, err := e.Client.CoreV1().Secrets(e.Namespace).Get(ctx, e.SSHCredentialSecret, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	privateKey := secret.Data["id_ed25519"]
	if len(privateKey) == 0 {
		return "", errors.New("SSH credential Secret has no id_ed25519 key")
	}
	return recoveryInputDigest(knownHosts, privateKey), nil
}

func recoveryInputDigest(knownHosts string, privateKey []byte) string {
	input := make([]byte, 0, len("kordex-recovery-input-v1\x00")+len(knownHosts)+1+len(privateKey))
	input = append(input, "kordex-recovery-input-v1\x00"...)
	input = append(input, knownHosts...)
	input = append(input, 0)
	input = append(input, privateKey...)
	digest := sha256.Sum256(input)
	return hex.EncodeToString(digest[:])
}

// Ensure creates the immutable request and one-shot Job, or verifies that an
// existing pair belongs to the exact operation, phase, target, and plan.
func (e *AnsibleJobExecutor) Ensure(ctx context.Context, request AnsibleJobRequest) (string, error) {
	if err := e.Validate(); err != nil {
		return "", err
	}
	if err := e.validateRequest(request); err != nil {
		return "", err
	}
	jobName := eeJobNameForRequest(request)
	if err := e.ensureEgressNetworkPolicy(ctx, request, jobName); err != nil {
		return "", err
	}
	if request.RecoveryTrustDigest != "" {
		if err := e.ensureRecoveryKnownHostsSnapshot(ctx, request, jobName); err != nil {
			return "", err
		}
	}
	if cancelled, err := e.cancellationTombstone(ctx, request, jobName); err != nil {
		return "", err
	} else if cancelled {
		return "", ErrExecutionCancelled
	}
	if _, receiptExists, _, receiptErr := e.readStoredReceipt(ctx, request, jobName); receiptErr != nil {
		return "", receiptErr
	} else if receiptExists {
		return jobName, nil
	}
	requestData, err := json.Marshal(eeRequestFile{
		OperationID:      request.OperationID,
		Phase:            request.Phase,
		PlanDigest:       request.PlanDigest,
		RebootAuthorized: request.RebootAuthorized,
		Node:             eeNode{Name: request.NodeName, UID: request.NodeUID, Address: canonicalIP(request.Address), MachineID: request.MachineID, BootID: request.BootID},
		Policy:           request.Policy,
	})
	if err != nil {
		return "", fmt.Errorf("encode Ansible EE request: %w", err)
	}
	createdRequest, err := e.ensureRequestConfigMap(ctx, request, jobName, requestData)
	if err != nil {
		return "", err
	}
	if !createdRequest {
		actual, getErr := e.Client.BatchV1().Jobs(e.Namespace).Get(ctx, jobName, metav1.GetOptions{})
		if apierrors.IsNotFound(getErr) {
			if _, receiptExists, _, receiptErr := e.readStoredReceipt(ctx, request, jobName); receiptErr != nil {
				return "", receiptErr
			} else if receiptExists {
				return jobName, nil
			}
			// A durable request with no Job is ambiguous: it may have been
			// submitted and then removed. Never recreate potentially completed work.
			return "", ErrExecutionNotFound
		}
		if getErr != nil {
			return "", getErr
		}
		if identityErr := e.verifyEEJobIdentity(actual, request); identityErr != nil {
			return "", identityErr
		}
		return actual.Name, nil
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
		if identityErr := e.verifyEEJobIdentity(actual, request); identityErr != nil {
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
	if err = e.verifyEEJobIdentity(actual, request); err != nil {
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

// Start activates the prepared suspended Job. The caller must persist the
// returned execution reference in its durable operation checkpoint before
// calling Start. Repeated calls are safe and never create replacement Jobs.
func (e *AnsibleJobExecutor) Start(ctx context.Context, request AnsibleJobRequest, reference string) error {
	if err := e.Validate(); err != nil {
		return err
	}
	if err := e.validateRequest(request); err != nil {
		return err
	}
	if reference != eeJobNameForRequest(request) {
		return ErrExecutionIdentity
	}
	if err := e.ensureEgressNetworkPolicy(ctx, request, reference); err != nil {
		return err
	}
	if cancelled, err := e.cancellationTombstone(ctx, request, reference); err != nil {
		return err
	} else if cancelled {
		return ErrExecutionCancelled
	}
	job, err := e.Client.BatchV1().Jobs(e.Namespace).Get(ctx, reference, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return ErrExecutionNotFound
		}
		return err
	}
	if err = e.verifyEEJobIdentity(job, request); err != nil {
		return err
	}
	if job.Spec.Suspend == nil || !*job.Spec.Suspend {
		return nil
	}
	job.Spec.Suspend = boolptr(false)
	_, err = e.Client.BatchV1().Jobs(e.Namespace).Update(ctx, job, metav1.UpdateOptions{})
	if apierrors.IsConflict(err) {
		job, err = e.Client.BatchV1().Jobs(e.Namespace).Get(ctx, reference, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if err = e.verifyEEJobIdentity(job, request); err != nil {
			return err
		}
		if job.Spec.Suspend == nil || !*job.Spec.Suspend {
			return nil
		}
		job.Spec.Suspend = boolptr(false)
		_, err = e.Client.BatchV1().Jobs(e.Namespace).Update(ctx, job, metav1.UpdateOptions{})
	}
	return err
}

func (e *AnsibleJobExecutor) Observe(ctx context.Context, request AnsibleJobRequest, reference string) (AnsibleJobObservation, error) {
	if err := e.Validate(); err != nil {
		return AnsibleJobObservation{}, err
	}
	if err := e.validateRequest(request); err != nil {
		return AnsibleJobObservation{}, err
	}
	expected := eeJobNameForRequest(request)
	if reference != expected {
		return AnsibleJobObservation{}, ErrExecutionIdentity
	}
	storedReceipt, receiptExists, storedDigest, receiptErr := e.readStoredReceipt(ctx, request, reference)
	if receiptErr != nil {
		return AnsibleJobObservation{}, receiptErr
	}
	if receiptExists {
		e.removeEgressNetworkPolicyWhenIdle(ctx, request, reference)
		return successfulObservation(request, reference, storedReceipt, storedDigest), nil
	}
	if cancelled, tombstoneErr := e.cancellationTombstone(ctx, request, reference); tombstoneErr != nil {
		return AnsibleJobObservation{}, tombstoneErr
	} else if cancelled {
		e.removeEgressNetworkPolicyWhenIdle(ctx, request, reference)
		return AnsibleJobObservation{Name: reference, Phase: "RecoveryRequired", Outcome: "Ambiguous", Reason: "CancellationRequested", ObservedAt: time.Now().UTC()}, nil
	}
	job, err := e.Client.BatchV1().Jobs(e.Namespace).Get(ctx, reference, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		e.removeEgressNetworkPolicyWhenIdle(ctx, request, reference)
		return AnsibleJobObservation{}, ErrExecutionNotFound
	}
	if err != nil {
		return AnsibleJobObservation{}, err
	}
	if err = e.verifyEEJobIdentity(job, request); err != nil {
		return AnsibleJobObservation{}, err
	}
	if err = e.ensureEgressNetworkPolicy(ctx, request, reference); err != nil {
		return AnsibleJobObservation{}, err
	}
	observation := AnsibleJobObservation{Name: job.Name, Phase: "Running", ObservedAt: time.Now().UTC()}
	if job.Spec.Suspend != nil && *job.Spec.Suspend {
		observation.Phase = "Prepared"
		return observation, nil
	}
	if job.Status.Succeeded > 0 {
		observation.Phase = "Succeeded"
		receipt, receiptErr := e.readReceipt(ctx, job, request)
		if receiptErr != nil {
			observation.Phase = "RecoveryRequired"
			observation.Outcome = "Ambiguous"
			observation.Reason = "ReceiptUnavailable"
			return observation, receiptErr
		}
		receiptDigest, persistErr := e.persistReceipt(ctx, request, reference, receipt)
		if persistErr != nil {
			observation.Phase = "RecoveryRequired"
			observation.Outcome = "Ambiguous"
			observation.Reason = "ReceiptPersistenceFailed"
			return observation, persistErr
		}
		observation.Outcome = "Succeeded"
		observation.Receipt = receipt
		observation.ReceiptReference = reference + "-receipt"
		observation.ReceiptDigest = receiptDigest
		e.removeEgressNetworkPolicyWhenIdle(ctx, request, reference)
		return observation, nil
	}
	if job.Status.Failed > 0 {
		observation.Phase = "RecoveryRequired"
		observation.Outcome = "Ambiguous"
		observation.Reason = "ExecutionJobFailed"
		eeReason := e.failedJobReason(ctx, job.Name)
		if eeReason != "ExecutionJobFailed" {
			observation.Reason = eeReason
			e.removeEgressNetworkPolicyWhenIdle(ctx, request, reference)
			return observation, nil
		}
		for _, condition := range job.Status.Conditions {
			if condition.Type == batchv1.JobFailed && condition.Status == corev1.ConditionTrue {
				observation.Reason = safeReason(condition.Reason, "ExecutionJobFailed")
				break
			}
		}
		e.removeEgressNetworkPolicyWhenIdle(ctx, request, reference)
	}
	return observation, nil
}

func (e *AnsibleJobExecutor) failedJobReason(ctx context.Context, jobName string) string {
	pods, err := e.Client.CoreV1().Pods(e.Namespace).List(ctx, metav1.ListOptions{LabelSelector: labels.Set{eeJobLabel: jobName}.AsSelector().String()})
	if err != nil {
		return "ExecutionJobFailed"
	}
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.Status.Phase != corev1.PodFailed {
			continue
		}
		for _, status := range pod.Status.ContainerStatuses {
			if status.Name == "ansible-ee" && status.State.Terminated != nil {
				if reason := eeFailureReason(status.State.Terminated.Message); reason != "" {
					return reason
				}
			}
		}
	}
	return "ExecutionJobFailed"
}

func eeFailureReason(message string) string {
	lines := strings.Split(message, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(line, eeErrorPrefix) {
			continue
		}
		reason := strings.TrimPrefix(line, eeErrorPrefix)
		switch reason {
		case "SSHHostKeyVerificationFailed", "SSHAuthenticationFailed", "SSHTransportUnavailable", "PlaybookFailedAmbiguous", "ExecutionTimedOutAmbiguous", "ExecutionInterruptedAmbiguous", "ExecutionEnvironmentUnavailable", "ReceiptUnavailable":
			return reason
		default:
			return "ExecutionJobFailed"
		}
	}
	return "ExecutionJobFailed"
}

// Cancel requests Kubernetes Job deletion but does not claim the remote host
// stopped. The caller must verify node/workload recovery because SSH loss can
// occur after apt or reboot was already issued.
func (e *AnsibleJobExecutor) Cancel(ctx context.Context, request AnsibleJobRequest, reference string) error {
	if err := e.Validate(); err != nil {
		return err
	}
	if err := e.validateRequest(request); err != nil {
		return err
	}
	if reference != eeJobNameForRequest(request) {
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
	if err = e.verifyEEJobIdentity(job, request); err != nil {
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
	if !protocol.ValidUUID(request.OperationID) || request.OwnerName != "op-"+request.OperationID || request.OwnerUID == "" || !protocol.ValidDNS1123Subdomain(request.NodeName) || request.NodeUID == "" || !protocol.ValidSHA256Digest(request.PlanDigest) {
		return errors.New("invalid Ansible EE operation or target identity")
	}
	if request.Phase != EEPhasePreflight && request.Phase != EEPhaseApply && request.Phase != EEPhaseReboot && request.Phase != EEPhaseInspect {
		return errors.New("unsupported Ansible EE job phase")
	}
	if !validSSHHostAddress(request.Address) {
		return errors.New("Ansible EE target must be a unicast node IP and cannot be loopback, unspecified, multicast, or link-local")
	}
	if err := request.Policy.Validate(); err != nil {
		return fmt.Errorf("invalid Ansible EE policy: %w", err)
	}
	digest, err := request.Policy.Digest()
	if err != nil || digest != request.PlanDigest {
		return errors.New("Ansible EE policy digest does not match signed operation")
	}
	if len(request.Policy.PreHooks) != 0 || len(request.Policy.PostHooks) != 0 {
		return errors.New("the initial Ansible EE catalog does not support pre or post hooks")
	}
	if request.Phase == EEPhasePreflight && (request.MachineID != "" || request.BootID != "") {
		return errors.New("preflight must discover host machine and boot identity")
	}
	if (request.Phase == EEPhaseApply || request.Phase == EEPhaseReboot || request.Phase == EEPhaseInspect) && (!validMachineID(request.MachineID) || !protocol.ValidUUID(request.BootID)) {
		return errors.New("apply, reboot, and inspect require preflighted machine and boot identity")
	}
	if request.Phase == EEPhaseReboot && request.Policy.Reboot == protocol.RebootNever {
		return errors.New("reboot phase is not allowed by the signed package plan")
	}
	if request.RebootAuthorized != (request.Phase == EEPhaseReboot) {
		return errors.New("explicit reboot authorization must match the reboot phase")
	}
	return nil
}

func (e *AnsibleJobExecutor) validateRequest(request AnsibleJobRequest) error {
	if err := validateEERequest(request); err != nil {
		return err
	}
	if request.RecoveryTrustDigest != "" {
		if request.Phase != EEPhaseInspect || request.RecoveryAttempt < 1 || request.RecoveryAttempt > 100 || !protocol.ValidSHA256Digest(request.RecoveryTrustDigest) || request.RecoveryRetryToken != "" && !protocol.ValidUUID(request.RecoveryRetryToken) {
			return ErrExecutionIdentity
		}
	} else if request.RecoveryAttempt != 0 {
		return ErrExecutionIdentity
	}
	for _, image := range e.AllowedExecutionEnvironments {
		if request.Policy.ExecutionEnvironment == image {
			return nil
		}
	}
	return errors.New("Ansible EE execution environment is not in the operator allowlist")
}

func (e *AnsibleJobExecutor) ensureRequestConfigMap(ctx context.Context, request AnsibleJobRequest, jobName string, data []byte) (bool, error) {
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
		return true, nil
	}
	actual, getErr := e.Client.CoreV1().ConfigMaps(e.Namespace).Get(ctx, cm.Name, metav1.GetOptions{})
	if getErr != nil {
		return false, fmt.Errorf("create or resolve immutable Ansible EE request: %w", err)
	}
	if actual.Immutable == nil || !*actual.Immutable || actual.Data["request.json"] != string(data) || actual.Annotations[eeDigestAnnotation] != request.PlanDigest || !hasOwnerUID(actual.OwnerReferences, request.OwnerUID) {
		return false, ErrExecutionIdentity
	}
	return false, nil
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
	annotations := map[string]string{eeDigestAnnotation: request.PlanDigest}
	knownHostsName := e.KnownHostsConfigMap
	if request.RecoveryTrustDigest != "" {
		annotations[eeTrustAnnotation] = request.RecoveryTrustDigest
		annotations["operations.kordex.local/recovery-attempt"] = fmt.Sprint(request.RecoveryAttempt)
		knownHostsName = recoveryKnownHostsSnapshotName(name)
	}
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: e.Namespace, Name: name, Labels: labelsForJob,
			Annotations:     annotations,
			OwnerReferences: []metav1.OwnerReference{owner},
		},
		Spec: batchv1.JobSpec{
			BackoffLimit: &backoff, Completions: &completions, Parallelism: &parallelism,
			ActiveDeadlineSeconds: &deadline, Suspend: &trueValue,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labelsForJob, Annotations: annotations},
				Spec: corev1.PodSpec{
					HostNetwork:                   false,
					HostPID:                       false,
					HostIPC:                       false,
					ShareProcessNamespace:         boolptr(false),
					EnableServiceLinks:            boolptr(false),
					DNSPolicy:                     corev1.DNSClusterFirst,
					RestartPolicy:                 corev1.RestartPolicyNever,
					TerminationGracePeriodSeconds: int64ptr(30),
					ServiceAccountName:            e.ServiceAccount,
					AutomountServiceAccountToken:  &falseValue,
					ImagePullSecrets:              imagePullSecrets,
					SecurityContext:               &corev1.PodSecurityContext{RunAsNonRoot: &trueValue, RunAsUser: int64ptr(1000), RunAsGroup: int64ptr(1000), FSGroup: int64ptr(1000), SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}},
					Containers: []corev1.Container{{
						Name: "ansible-ee", Image: request.Policy.ExecutionEnvironment, ImagePullPolicy: corev1.PullIfNotPresent,
						Command: []string{"/usr/local/bin/kordex-upgrade"}, Args: []string{"--request=/etc/kordex/request.json", "--result=/var/run/kordex/result.json"},
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
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
						{Name: "known-hosts", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: knownHostsName}, DefaultMode: int32ptr(0444), Items: []corev1.KeyToPath{{Key: "known_hosts", Path: "known_hosts"}}}}},
						{Name: "work", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{SizeLimit: resourceQuantityPtr("128Mi")}}},
					},
				},
			},
		},
	}
}

func (e *AnsibleJobExecutor) ensureEgressNetworkPolicy(ctx context.Context, request AnsibleJobRequest, jobName string) error {
	ip := net.ParseIP(request.Address)
	if ip == nil {
		return ErrExecutionIdentity
	}
	prefix := 128
	if ip.To4() != nil {
		ip = ip.To4()
		prefix = 32
	} else {
		ip = ip.To16()
	}
	peer := ip.String() + fmt.Sprintf("/%d", prefix)
	protocolTCP := corev1.ProtocolTCP
	port22 := intstr.FromInt32(22)
	policy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: e.Namespace,
			Name:      eeNetworkPolicyName(jobName),
			Labels:    eeLabels(request),
			Annotations: map[string]string{
				eeDigestAnnotation: request.PlanDigest,
				eeTargetAnnotation: canonicalIP(request.Address),
			},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: protocol.OperationGroup + "/" + protocol.OperationVersion,
				Kind:       "NodeMaintenance", Name: request.OwnerName, UID: request.OwnerUID,
			}},
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{eeJobLabel: jobName}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
			Egress: []networkingv1.NetworkPolicyEgressRule{{
				To:    []networkingv1.NetworkPolicyPeer{{IPBlock: &networkingv1.IPBlock{CIDR: peer}}},
				Ports: []networkingv1.NetworkPolicyPort{{Protocol: &protocolTCP, Port: &port22}},
			}},
		},
	}
	if err := e.rejectOverlappingEgressAllows(ctx, policy.Name, request, jobName); err != nil {
		return err
	}
	policies := e.Client.NetworkingV1().NetworkPolicies(e.Namespace)
	_, err := policies.Create(ctx, policy, metav1.CreateOptions{})
	if err == nil {
		return nil
	}
	if !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create Ansible EE egress policy: %w", err)
	}
	actual, getErr := policies.Get(ctx, policy.Name, metav1.GetOptions{})
	if getErr != nil {
		return fmt.Errorf("create or read Ansible EE egress policy: %w", getErr)
	}
	if !apiequality.Semantic.DeepEqual(actual.Spec, policy.Spec) || actual.Annotations[eeDigestAnnotation] != request.PlanDigest || actual.Annotations[eeTargetAnnotation] != canonicalIP(request.Address) || !hasOwnerUID(actual.OwnerReferences, request.OwnerUID) {
		return ErrExecutionIdentity
	}
	return nil
}

// NetworkPolicy allows are additive. Refuse to run an EE pod if another
// standard policy selects it and contributes any egress allow rule.
func (e *AnsibleJobExecutor) rejectOverlappingEgressAllows(ctx context.Context, ownPolicyName string, request AnsibleJobRequest, jobName string) error {
	items, err := e.Client.NetworkingV1().NetworkPolicies(e.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list policies before isolating Ansible EE job: %w", err)
	}
	podLabels := eeLabels(request)
	podLabels[eeJobLabel] = jobName
	for i := range items.Items {
		candidate := &items.Items[i]
		if candidate.Name == ownPolicyName || len(candidate.Spec.Egress) == 0 {
			continue
		}
		selector, selectorErr := metav1.LabelSelectorAsSelector(&candidate.Spec.PodSelector)
		if selectorErr != nil {
			return fmt.Errorf("existing NetworkPolicy %q has an invalid pod selector: %w", candidate.Name, selectorErr)
		}
		if selector.Matches(labels.Set(podLabels)) {
			return fmt.Errorf("existing NetworkPolicy %q also allows egress for Ansible EE job pods", candidate.Name)
		}
	}
	return nil
}

func eeNetworkPolicyName(jobName string) string { return jobName + "-egress" }

// Keep a restrictive policy until all Job pods have stopped. A list failure
// intentionally retains the policy; cleanup failure must never widen access.
func (e *AnsibleJobExecutor) removeEgressNetworkPolicyWhenIdle(ctx context.Context, request AnsibleJobRequest, jobName string) {
	pods, err := e.Client.CoreV1().Pods(e.Namespace).List(ctx, metav1.ListOptions{LabelSelector: labels.Set{eeJobLabel: jobName}.AsSelector().String()})
	if err != nil {
		return
	}
	for i := range pods.Items {
		phase := pods.Items[i].Status.Phase
		if phase != corev1.PodSucceeded && phase != corev1.PodFailed {
			return
		}
	}
	policies := e.Client.NetworkingV1().NetworkPolicies(e.Namespace)
	policy, err := policies.Get(ctx, eeNetworkPolicyName(jobName), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return
	}
	if err != nil || policy.Annotations[eeDigestAnnotation] != request.PlanDigest || !hasOwnerUID(policy.OwnerReferences, request.OwnerUID) {
		return
	}
	if err := policies.Delete(ctx, policy.Name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		return
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
	if err := validateReceipt(request, receipt, job.CreationTimestamp.Time, time.Now().Add(5*time.Second)); err != nil {
		return nil, ErrExecutionReceipt
	}
	return receipt, nil
}

func validateReceipt(request AnsibleJobRequest, receipt *AnsibleReceipt, notBefore, notAfter time.Time) error {
	if receipt == nil || receipt.OperationID != request.OperationID || receipt.PlanDigest != request.PlanDigest || receipt.NodeUID != request.NodeUID || !validMachineID(receipt.MachineID) || !protocol.ValidUUID(receipt.BootIDBefore) || !protocol.ValidUUID(receipt.BootIDAfter) || receipt.OSFamily != request.Policy.OSFamily || receipt.CompletedAt.IsZero() || !notBefore.IsZero() && receipt.CompletedAt.Before(notBefore.Add(-time.Second)) || !notAfter.IsZero() && receipt.CompletedAt.After(notAfter) {
		return ErrExecutionReceipt
	}
	if request.Phase == EEPhasePreflight {
		if len(receipt.Packages) != 0 || receipt.ActionMarker != nil || receipt.Rebooted || receipt.RebootRequired || receipt.BootIDBefore != receipt.BootIDAfter || !protocol.ValidKernelVersion(receipt.KernelVersion) || receipt.ExpectedKernelVersion != request.Policy.ExpectedKernelVersion {
			return ErrExecutionReceipt
		}
		if receipt.BaselinePackages != nil {
			if len(receipt.BaselinePackages) != len(request.Policy.Packages) {
				return ErrExecutionReceipt
			}
			for _, pin := range request.Policy.Packages {
				version, ok := receipt.BaselinePackages[pin.Name]
				if !ok || len(version) > 256 || strings.ContainsAny(version, "\r\n\x00") {
					return ErrExecutionReceipt
				}
			}
		}
	} else {
		if len(receipt.BaselinePackages) != 0 {
			return ErrExecutionReceipt
		}
		if receipt.MachineID != request.MachineID || request.Phase != EEPhaseInspect && receipt.BootIDBefore != request.BootID || receipt.ExpectedKernelVersion != request.Policy.ExpectedKernelVersion || !protocol.ValidKernelVersion(receipt.KernelVersion) {
			return ErrExecutionReceipt
		}
		switch request.Phase {
		case EEPhaseApply:
			if receipt.Rebooted || receipt.BootIDAfter != receipt.BootIDBefore || request.Policy.Reboot == protocol.RebootRequired && !receipt.RebootRequired || request.Policy.Reboot == protocol.RebootNever && receipt.RebootRequired {
				return ErrExecutionReceipt
			}
		case EEPhaseInspect:
			if receipt.Rebooted || receipt.BootIDAfter != receipt.BootIDBefore {
				return ErrExecutionReceipt
			}
		case EEPhaseReboot:
			if !receipt.Rebooted || !receipt.RebootRequired || receipt.BootIDAfter == receipt.BootIDBefore || request.Policy.ExpectedKernelVersion != "" && receipt.KernelVersion != request.Policy.ExpectedKernelVersion {
				return ErrExecutionReceipt
			}
		}
		if receipt.Rebooted != (receipt.BootIDBefore != receipt.BootIDAfter) {
			return ErrExecutionReceipt
		}
		if len(receipt.Packages) != len(request.Policy.Packages) {
			return ErrExecutionReceipt
		}
		for _, item := range request.Policy.Packages {
			if receipt.Packages[item.Name] != item.Version {
				return ErrExecutionReceipt
			}
		}
	}
	if request.Policy.ActionMarkerVersion == 1 {
		if request.Phase == EEPhaseApply || request.Phase == EEPhaseReboot {
			marker := receipt.ActionMarker
			wantPhase, wantSequence := "packages-verified", int64(2)
			wantBootID := receipt.BootIDBefore
			if request.Phase == EEPhaseReboot {
				wantPhase, wantSequence, wantBootID = "reboot-verified", 4, receipt.BootIDAfter
			}
			if marker == nil || marker.Validate() != nil || marker.OperationID != request.OperationID || marker.ActionDigest != request.PlanDigest || marker.NodeUID != request.NodeUID || marker.MachineID != receipt.MachineID || marker.BootID != wantBootID || marker.Phase != wantPhase || marker.Sequence != wantSequence {
				return ErrExecutionReceipt
			}
		} else if request.Phase == EEPhaseInspect && receipt.ActionMarker != nil {
			marker := receipt.ActionMarker
			if marker.Validate() != nil || marker.OperationID != request.OperationID || marker.ActionDigest != request.PlanDigest || marker.NodeUID != request.NodeUID || marker.MachineID != receipt.MachineID {
				return ErrExecutionReceipt
			}
		}
	} else if receipt.ActionMarker != nil {
		return ErrExecutionReceipt
	}
	return nil
}

func (e *AnsibleJobExecutor) readStoredReceipt(ctx context.Context, request AnsibleJobRequest, jobName string) (*AnsibleReceipt, bool, string, error) {
	ledgerNamespace := e.ledgerNamespace()
	cmName := upgradeReceiptNameForRequest(request)
	cm, err := e.Client.CoreV1().ConfigMaps(ledgerNamespace).Get(ctx, cmName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		// Read receipts written by releases before the independent ledger was
		// introduced. New receipts are always written to LedgerNamespace.
		legacy, legacyErr := e.Client.CoreV1().ConfigMaps(e.Namespace).Get(ctx, jobName+"-receipt", metav1.GetOptions{})
		if apierrors.IsNotFound(legacyErr) {
			return nil, false, "", nil
		}
		if legacyErr != nil {
			return nil, false, "", legacyErr
		}
		if legacy.Immutable == nil || !*legacy.Immutable || legacy.Annotations[eeDigestAnnotation] != request.PlanDigest || !hasOwnerUID(legacy.OwnerReferences, request.OwnerUID) || legacy.Labels[eeOperationLabel] != request.OperationID || legacy.Labels[eePhaseLabel] != request.Phase {
			return nil, false, "", ErrExecutionIdentity
		}
		var receipt AnsibleReceipt
		notAfter := time.Time{}
		if !legacy.CreationTimestamp.IsZero() {
			notAfter = legacy.CreationTimestamp.Add(5 * time.Second)
		}
		if json.Unmarshal([]byte(legacy.Data["receipt.json"]), &receipt) != nil || validateReceipt(request, &receipt, time.Time{}, notAfter) != nil {
			return nil, false, "", ErrExecutionReceipt
		}
		digest := sha256.Sum256([]byte(legacy.Data["receipt.json"]))
		if _, persistErr := e.persistReceipt(ctx, request, jobName, &receipt); persistErr != nil {
			return nil, false, "", persistErr
		}
		return &receipt, true, hex.EncodeToString(digest[:]), nil
	}
	if err != nil {
		return nil, false, "", err
	}
	if cm.Namespace != ledgerNamespace || cm.Name != cmName || cm.Immutable == nil || !*cm.Immutable || cm.Annotations[eeDigestAnnotation] != request.PlanDigest || cm.Labels[eeOperationLabel] != request.OperationID || cm.Labels[eePhaseLabel] != request.Phase || cm.Labels["operations.kordex.local/node-uid"] != request.NodeUID || len(cm.OwnerReferences) != 0 {
		return nil, false, "", ErrExecutionIdentity
	}
	var receipt AnsibleReceipt
	notAfter := time.Time{}
	if !cm.CreationTimestamp.IsZero() {
		notAfter = cm.CreationTimestamp.Add(5 * time.Second)
	}
	if json.Unmarshal([]byte(cm.Data["receipt.json"]), &receipt) != nil || validateReceipt(request, &receipt, time.Time{}, notAfter) != nil {
		return nil, false, "", ErrExecutionReceipt
	}
	digest := sha256.Sum256([]byte(cm.Data["receipt.json"]))
	return &receipt, true, hex.EncodeToString(digest[:]), nil
}

func (e *AnsibleJobExecutor) persistReceipt(ctx context.Context, request AnsibleJobRequest, jobName string, receipt *AnsibleReceipt) (string, error) {
	ledgerNamespace := e.ledgerNamespace()
	data, err := json.Marshal(receipt)
	if err != nil {
		return "", err
	}
	immutable := true
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
		Namespace:   ledgerNamespace,
		Name:        upgradeReceiptNameForRequest(request),
		Labels:      ledgerReceiptLabels(request),
		Annotations: map[string]string{eeDigestAnnotation: request.PlanDigest},
	}, Immutable: &immutable, Data: map[string]string{"receipt.json": string(data)}}
	_, err = e.Client.CoreV1().ConfigMaps(ledgerNamespace).Create(ctx, cm, metav1.CreateOptions{})
	if err == nil {
		digest := sha256.Sum256(data)
		return hex.EncodeToString(digest[:]), nil
	}
	actual, getErr := e.Client.CoreV1().ConfigMaps(ledgerNamespace).Get(ctx, cm.Name, metav1.GetOptions{})
	if getErr != nil {
		return "", fmt.Errorf("create or resolve immutable Ansible EE receipt: %w", err)
	}
	if actual.Immutable == nil || !*actual.Immutable || actual.Data["receipt.json"] != string(data) || actual.Annotations[eeDigestAnnotation] != request.PlanDigest || len(actual.OwnerReferences) != 0 || actual.Labels[eeOperationLabel] != request.OperationID || actual.Labels[eePhaseLabel] != request.Phase || actual.Labels["operations.kordex.local/node-uid"] != request.NodeUID {
		return "", ErrExecutionIdentity
	}
	digest := sha256.Sum256([]byte(actual.Data["receipt.json"]))
	return hex.EncodeToString(digest[:]), nil
}

func upgradeReceiptName(operationID, phase string) string {
	return "upgrade-" + operationID + "-" + phase
}

func upgradeReceiptNameForRequest(request AnsibleJobRequest) string {
	if request.RecoveryTrustDigest == "" {
		return upgradeReceiptName(request.OperationID, request.Phase)
	}
	opDigest := sha256.Sum256([]byte(request.OperationID))
	return "ur-" + hex.EncodeToString(opDigest[:])[:16] + "-" + request.RecoveryTrustDigest[:18]
}

func ledgerReceiptLabels(request AnsibleJobRequest) map[string]string {
	return map[string]string{
		eeJobLabel:                         "true",
		eeOperationLabel:                   request.OperationID,
		eePhaseLabel:                       request.Phase,
		"operations.kordex.local/node-uid": request.NodeUID,
	}
}

func successfulObservation(request AnsibleJobRequest, reference string, receipt *AnsibleReceipt, digest string) AnsibleJobObservation {
	return AnsibleJobObservation{Name: reference, Phase: "Succeeded", Outcome: "Succeeded", Receipt: receipt, ReceiptReference: upgradeReceiptNameForRequest(request), ReceiptDigest: digest, ObservedAt: time.Now().UTC()}
}

func (e *AnsibleJobExecutor) verifyEEJobIdentity(job *batchv1.Job, request AnsibleJobRequest) error {
	if job == nil {
		return ErrExecutionIdentity
	}
	if job.Name != eeJobNameForRequest(request) || job.Labels[eeOperationLabel] != request.OperationID || job.Labels[eePhaseLabel] != request.Phase || job.Annotations[eeDigestAnnotation] != request.PlanDigest || job.Annotations[eeTrustAnnotation] != request.RecoveryTrustDigest || request.RecoveryTrustDigest != "" && job.Annotations["operations.kordex.local/recovery-attempt"] != fmt.Sprint(request.RecoveryAttempt) || !hasOwnerUID(job.OwnerReferences, request.OwnerUID) {
		return ErrExecutionIdentity
	}
	expected := e.job(request, job.Name)
	actualPod := &job.Spec.Template.Spec
	expectedPod := &expected.Spec.Template.Spec
	if len(actualPod.Containers) != 1 || len(expectedPod.Containers) != 1 {
		return ErrExecutionIdentity
	}
	actualContainer, expectedContainer := actualPod.Containers[0], expectedPod.Containers[0]
	if job.Namespace != e.Namespace || !apiequality.Semantic.DeepEqual(job.OwnerReferences, expected.OwnerReferences) ||
		!apiequality.Semantic.DeepEqual(job.Labels, expected.Labels) || !apiequality.Semantic.DeepEqual(job.Annotations, expected.Annotations) ||
		!apiequality.Semantic.DeepEqual(job.Spec.Template.Labels, expected.Spec.Template.Labels) ||
		!apiequality.Semantic.DeepEqual(job.Spec.Template.Annotations, expected.Spec.Template.Annotations) ||
		actualPod.ServiceAccountName != e.ServiceAccount || actualPod.AutomountServiceAccountToken == nil || *actualPod.AutomountServiceAccountToken ||
		actualPod.RestartPolicy != corev1.RestartPolicyNever || actualPod.HostNetwork || actualPod.HostPID || actualPod.HostIPC ||
		actualPod.NodeName != "" || len(actualPod.InitContainers) != 0 || len(actualPod.EphemeralContainers) != 0 ||
		actualPod.ShareProcessNamespace != nil && *actualPod.ShareProcessNamespace || actualPod.HostUsers != nil && !*actualPod.HostUsers ||
		!apiequality.Semantic.DeepEqual(actualPod.SecurityContext, expectedPod.SecurityContext) ||
		!apiequality.Semantic.DeepEqual(actualPod.ImagePullSecrets, expectedPod.ImagePullSecrets) ||
		!apiequality.Semantic.DeepEqual(actualPod.Volumes, expectedPod.Volumes) ||
		actualContainer.Name != expectedContainer.Name || actualContainer.Image != expectedContainer.Image ||
		actualContainer.ImagePullPolicy != expectedContainer.ImagePullPolicy ||
		!apiequality.Semantic.DeepEqual(actualContainer.Command, expectedContainer.Command) ||
		!apiequality.Semantic.DeepEqual(actualContainer.Args, expectedContainer.Args) ||
		!apiequality.Semantic.DeepEqual(actualContainer.Env, expectedContainer.Env) ||
		!apiequality.Semantic.DeepEqual(actualContainer.EnvFrom, expectedContainer.EnvFrom) ||
		!apiequality.Semantic.DeepEqual(actualContainer.SecurityContext, expectedContainer.SecurityContext) ||
		!apiequality.Semantic.DeepEqual(actualContainer.VolumeMounts, expectedContainer.VolumeMounts) ||
		!apiequality.Semantic.DeepEqual(actualContainer.Resources, expectedContainer.Resources) ||
		!apiequality.Semantic.DeepEqual(actualContainer.Ports, expectedContainer.Ports) ||
		!apiequality.Semantic.DeepEqual(actualContainer.Lifecycle, expectedContainer.Lifecycle) ||
		actualContainer.TerminationMessagePath != expectedContainer.TerminationMessagePath || actualContainer.TerminationMessagePolicy != expectedContainer.TerminationMessagePolicy ||
		actualContainer.WorkingDir != expectedContainer.WorkingDir || actualContainer.Stdin || actualContainer.TTY {
		return ErrExecutionIdentity
	}
	if job.Spec.Suspend == nil || job.Spec.BackoffLimit == nil || *job.Spec.BackoffLimit != 0 ||
		job.Spec.Completions == nil || *job.Spec.Completions != 1 || job.Spec.Parallelism == nil || *job.Spec.Parallelism != 1 ||
		job.Spec.ActiveDeadlineSeconds == nil || expected.Spec.ActiveDeadlineSeconds == nil || *job.Spec.ActiveDeadlineSeconds != *expected.Spec.ActiveDeadlineSeconds {
		return ErrExecutionIdentity
	}
	return nil
}

func boolptr(value bool) *bool { return &value }

func eeLabels(request AnsibleJobRequest) map[string]string {
	return map[string]string{eeOperationLabel: request.OperationID, eePhaseLabel: request.Phase}
}

func eeJobName(operationID, phase string) string {
	return "kordex-ee-" + strings.ReplaceAll(operationID, "-", "") + "-" + phase
}

func AnsibleJobReference(operationID, phase string) string {
	return eeJobName(operationID, phase)
}

func recoveryInspectionReference(operationID, trustDigest string, attempt int32) string {
	opDigest := sha256.Sum256([]byte(operationID))
	return "kordex-ee-" + hex.EncodeToString(opDigest[:])[:16] + "-inspect-" + trustDigest[:18] + "-" + fmt.Sprint(attempt)
}

// AnsibleInspectionReference creates a unique bounded Job name for an
// immutable read-only inspection attempt associated with a trust-data digest.
func AnsibleInspectionReference(operationID, trustDigest string) string {
	if !protocol.ValidUUID(operationID) || !protocol.ValidSHA256Digest(trustDigest) {
		return ""
	}
	return recoveryInspectionReference(operationID, trustDigest, 1)
}

// AnsibleInspectionAttemptReference names an immutable read-only inspection
// attempt, including a retry after SSH transport recovery.
func AnsibleInspectionAttemptReference(operationID, trustDigest string, attempt int32) string {
	if !protocol.ValidUUID(operationID) || !protocol.ValidSHA256Digest(trustDigest) || attempt < 1 || attempt > 100 {
		return ""
	}
	return recoveryInspectionReference(operationID, trustDigest, attempt)
}

func eeJobNameForRequest(request AnsibleJobRequest) string {
	if request.Phase == EEPhaseInspect && request.RecoveryTrustDigest != "" {
		return recoveryInspectionReference(request.OperationID, request.RecoveryTrustDigest, request.RecoveryAttempt)
	}
	return eeJobName(request.OperationID, request.Phase)
}

func recoveryKnownHostsSnapshotName(jobName string) string {
	digest := sha256.Sum256([]byte(jobName))
	return "kordex-hosts-" + hex.EncodeToString(digest[:])[:50]
}

func (e *AnsibleJobExecutor) ensureRecoveryKnownHostsSnapshot(ctx context.Context, request AnsibleJobRequest, jobName string) error {
	name := recoveryKnownHostsSnapshotName(jobName)
	if actual, err := e.Client.CoreV1().ConfigMaps(e.Namespace).Get(ctx, name, metav1.GetOptions{}); err == nil {
		if actual.Immutable == nil || !*actual.Immutable || actual.Annotations[eeTrustAnnotation] != request.RecoveryTrustDigest || actual.Annotations["operations.kordex.local/job-reference"] != jobName || !hasOwnerUID(actual.OwnerReferences, request.OwnerUID) {
			return ErrExecutionIdentity
		}
		return nil
	} else if !apierrors.IsNotFound(err) {
		return err
	}
	source, err := e.Client.CoreV1().ConfigMaps(e.Namespace).Get(ctx, e.KnownHostsConfigMap, metav1.GetOptions{})
	if err != nil {
		return err
	}
	secret, err := e.Client.CoreV1().Secrets(e.Namespace).Get(ctx, e.SSHCredentialSecret, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if recoveryInputDigest(source.Data["known_hosts"], secret.Data["id_ed25519"]) != request.RecoveryTrustDigest {
		return errors.New("recovery trust or SSH credentials changed while preparing inspection")
	}
	immutable, controller, blockOwnerDeletion := true, true, false
	labels := eeLabels(request)
	annotations := map[string]string{eeTrustAnnotation: request.RecoveryTrustDigest, "operations.kordex.local/job-reference": jobName}
	owner := metav1.OwnerReference{APIVersion: protocol.OperationGroup + "/" + protocol.OperationVersion, Kind: "NodeMaintenance", Name: request.OwnerName, UID: request.OwnerUID, Controller: &controller, BlockOwnerDeletion: &blockOwnerDeletion}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: e.Namespace, Name: name, Labels: labels, Annotations: annotations, OwnerReferences: []metav1.OwnerReference{owner}}, Immutable: &immutable, Data: map[string]string{"known_hosts": source.Data["known_hosts"]}}
	_, createErr := e.Client.CoreV1().ConfigMaps(e.Namespace).Create(ctx, cm, metav1.CreateOptions{})
	if createErr != nil {
		actual, getErr := e.Client.CoreV1().ConfigMaps(e.Namespace).Get(ctx, name, metav1.GetOptions{})
		if getErr != nil {
			return fmt.Errorf("create or resolve immutable recovery known-hosts snapshot: %w", createErr)
		}
		if actual.Immutable == nil || !*actual.Immutable || actual.Data["known_hosts"] != source.Data["known_hosts"] || actual.Annotations[eeTrustAnnotation] != request.RecoveryTrustDigest || actual.Annotations["operations.kordex.local/job-reference"] != jobName || !hasOwnerUID(actual.OwnerReferences, request.OwnerUID) {
			return ErrExecutionIdentity
		}
	}
	return nil
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
func validSSHHostAddress(value string) bool {
	ip := net.ParseIP(value)
	if ip == nil {
		return false
	}
	if ipv4 := ip.To4(); ipv4 != nil {
		ip = ipv4
	}
	return ip.IsGlobalUnicast() && !ip.IsLinkLocalUnicast()
}
func int64ptr(value int64) *int64 { return &value }
func int32ptr(value int32) *int32 { return &value }

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
