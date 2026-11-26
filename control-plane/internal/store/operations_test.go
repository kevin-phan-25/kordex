package store_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"kordex.local/api/protocol"
	"kordex.local/control-plane/internal/store"
)

func TestDurableNodeOperationDelivery(t *testing.T) {
	dsn := os.Getenv("KORDEX_TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("CI") == "true" {
			t.Fatal("database required")
		}
		t.Skip("disposable database required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	db, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	requestID := store.NewID()
	org, err := db.CreateOrganization(ctx, "operations-"+store.NewID(), "test", requestID)
	if err != nil {
		t.Fatal(err)
	}
	site, err := db.CreateSite(ctx, org.ID, "lab", "local", "test", requestID)
	if err != nil {
		t.Fatal(err)
	}
	fleet, err := db.CreateFleet(ctx, org.ID, "lab", "test", requestID)
	if err != nil {
		t.Fatal(err)
	}
	cluster, err := db.CreateCluster(ctx, store.Cluster{OrganizationID: org.ID, FleetID: fleet.ID, SiteID: site.ID, Name: "cluster", Provider: "self-managed"}, "test", requestID)
	if err != nil {
		t.Fatal(err)
	}
	managedSite, err := db.CreateSite(ctx, org.ID, "managed-site", "remote", "test", requestID)
	if err != nil {
		t.Fatal(err)
	}
	managedCluster, err := db.CreateCluster(ctx, store.Cluster{OrganizationID: org.ID, FleetID: fleet.ID, SiteID: managedSite.ID, Name: "managed-cluster", Provider: "eks"}, "test", requestID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.RequestLabStop(ctx, org.ID, managedCluster.ID, "test", requestID); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("managed cluster entered the self-managed lab lifecycle: %v", err)
	}
	enrollment, err := db.IssueEnrollment(ctx, org.ID, cluster.ID, "test", requestID)
	if err != nil {
		t.Fatal(err)
	}
	agentPublic, agentPrivate, _ := ed25519.GenerateKey(rand.Reader)
	e := protocol.Enrollment{ClusterID: cluster.ID, ClusterUID: "test-kube-" + store.NewID(), Token: enrollment.Token, PublicKey: protocol.EncodeKey(agentPublic)}
	e.Proof = protocol.Proof(agentPrivate, protocol.EnrollmentMessage(e))
	if _, err = db.EnrollAgent(ctx, e, requestID); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	policy := protocol.PolicyReference{Name: "safe-workers", UID: "policy-uid", Generation: 1}
	catalog := &protocol.MaintenancePolicyCatalog{ObservedAt: now, Items: []protocol.MaintenancePolicyCatalogEntry{{Policy: policy, AllowedActions: []string{protocol.ValidateOnly}}}}
	if err = db.AcceptReport(ctx, cluster.ID, protocol.KeyID(agentPublic), "inventory-nonce", protocol.Report{ClusterUID: e.ClusterUID, Version: 1, ObservedAt: now, KubernetesVersion: "v1.37.0", Nodes: []protocol.Node{{UID: "worker-uid", Name: "worker1", Ready: true}}, PolicyCatalog: catalog}); err != nil {
		t.Fatal(err)
	}
	hubPublic, hubPrivate, _ := ed25519.GenerateKey(rand.Reader)
	disallowed := protocol.MaintenanceRequest{OperationID: store.NewID(), NodeName: "worker1", NodeUID: "worker-uid", Policy: policy, Action: protocol.DrainAndVerify}
	if _, err = db.CreateNodeOperation(ctx, org.ID, cluster.ID, disallowed, hubPrivate, "test", requestID); !errors.Is(err, store.ErrUpgradeAdmission) {
		t.Fatalf("central admission allowed an action missing from the policy catalog: %v", err)
	}
	input := protocol.MaintenanceRequest{OperationID: store.NewID(), NodeName: "worker1", NodeUID: "worker-uid", Policy: protocol.PolicyReference{Name: "safe-workers", UID: "policy-uid", Generation: 1}, Action: protocol.ValidateOnly}
	beforeSnapshot, err := db.SchedulerSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	op, err := db.CreateNodeOperation(ctx, org.ID, cluster.ID, input, hubPrivate, "test", requestID)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := db.SchedulerSnapshot(ctx)
	if err != nil || snapshot.ActiveReservations != beforeSnapshot.ActiveReservations+1 {
		t.Fatalf("new active reservation snapshot = %+v, err=%v", snapshot, err)
	}
	if _, err = db.Pool.Exec(ctx, `UPDATE operation_reservations SET created_at=now()-interval '91 seconds' WHERE operation_id=$1`, op.ID); err != nil {
		t.Fatal(err)
	}
	snapshot, err = db.SchedulerSnapshot(ctx)
	if err != nil || snapshot.ActiveReservations != beforeSnapshot.ActiveReservations+1 || snapshot.OldestReservationAge < 90 {
		t.Fatalf("aged active reservation snapshot = %+v, err=%v", snapshot, err)
	}
	spec, err := openapi3.NewLoader().LoadFromFile("../../../api/openapi/v1.json")
	if err != nil {
		t.Fatal(err)
	}
	validateResponse := func(op store.NodeOperation) {
		t.Helper()
		encoded, err := json.Marshal(op)
		if err != nil {
			t.Fatal(err)
		}
		var value any
		if err = json.Unmarshal(encoded, &value); err != nil {
			t.Fatal(err)
		}
		if err = spec.Components.Schemas["NodeOperation"].Value.VisitJSON(value); err != nil {
			t.Fatal(err)
		}
	}
	validateResponse(op)
	permit, err := protocol.DecodeMaintenance(op.Command, map[string]ed25519.PublicKey{protocol.KeyID(hubPublic): hubPublic})
	if err != nil || permit.ClusterUID != e.ClusterUID || permit.NodeUID != "worker-uid" {
		t.Fatalf("bad signed operation: %v", err)
	}
	for i := 0; i < 3; i++ {
		again, err := db.CreateNodeOperation(ctx, org.ID, cluster.ID, input, hubPrivate, "test", requestID)
		if err != nil || again.Command.Digest() != op.Command.Digest() {
			t.Fatal("idempotent create changed the signed command")
		}
	}
	conflicting := input
	conflicting.Action = protocol.DrainAndVerify
	if _, err = db.CreateNodeOperation(ctx, org.ID, cluster.ID, conflicting, hubPrivate, "test", requestID); !errors.Is(err, store.ErrConflict) {
		t.Fatal("operation ID reused with different action")
	}
	second := input
	second.OperationID = store.NewID()
	if _, err = db.CreateNodeOperation(ctx, org.ID, cluster.ID, second, hubPrivate, "test", requestID); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("cluster concurrency violated: %v", err)
	}
	first, err := db.SyncNodeOperations(ctx, cluster.ID, protocol.KeyID(agentPublic), "delivery-1", protocol.OperationSync{}, requestID)
	if err != nil || len(first.Commands) != 1 {
		t.Fatalf("command not delivered: %v", err)
	}
	repeated, err := db.SyncNodeOperations(ctx, cluster.ID, protocol.KeyID(agentPublic), "delivery-2", protocol.OperationSync{}, requestID)
	if err != nil || len(repeated.Commands) != 1 || repeated.Commands[0].Digest() != first.Commands[0].Digest() {
		t.Fatal("delivery retry changed identity")
	}
	if _, err = db.SyncNodeOperations(ctx, cluster.ID, protocol.KeyID(agentPublic), "delivery-2", protocol.OperationSync{}, requestID); !errors.Is(err, store.ErrUnauthorized) {
		t.Fatal("sync nonce replay accepted")
	}
	wrongAction := protocol.OperationReport{OperationID: op.ID, Sequence: 4, Phase: "Cordoning", Reason: "test"}
	for i, phase := range []string{"Pending", "Validating", "SafetyChecking", "Cordoning"} {
		wrongAction.Events = append(wrongAction.Events, protocol.PhaseEvent{Sequence: int64(i + 1), Phase: phase, Reason: "test", Time: metav1.Now()})
	}
	if _, err = db.SyncNodeOperations(ctx, cluster.ID, protocol.KeyID(agentPublic), "wrong-action-phases", protocol.OperationSync{Reports: []protocol.OperationReport{wrongAction}}, requestID); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("ValidateOnly operation accepted drain phases: %v", err)
	}
	status := protocol.OperationReport{OperationID: op.ID, Sequence: 1, Phase: "Pending", Reason: "RequestAccepted", Events: []protocol.PhaseEvent{{Sequence: 1, Phase: "Pending", Reason: "RequestAccepted", Time: metav1.Now()}}}
	future := status
	future.Events = append([]protocol.PhaseEvent(nil), status.Events...)
	future.Events[0].Time = metav1.NewTime(time.Now().Add(protocol.ClockSkew + time.Second))
	if _, err = db.SyncNodeOperations(ctx, cluster.ID, protocol.KeyID(agentPublic), "future-time", protocol.OperationSync{Reports: []protocol.OperationReport{future}}, requestID); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("future-dated operation report was accepted: %v", err)
	}
	ack, err := db.SyncNodeOperations(ctx, cluster.ID, protocol.KeyID(agentPublic), "status-1", protocol.OperationSync{Reports: []protocol.OperationReport{status}}, requestID)
	if err != nil || ack.Acknowledged[op.ID] != 1 {
		t.Fatalf("status not acknowledged: %v", err)
	}
	// A later report cannot rewrite the already-audited prefix.
	tampered := status
	tampered.Events = append([]protocol.PhaseEvent(nil), status.Events...)
	tampered.Events[0].Reason = "changed-history"
	tampered.Events = append(tampered.Events, protocol.PhaseEvent{Sequence: 2, Phase: "Validating", Reason: "AuthorizationValidated", Time: metav1.Now()})
	tampered.Sequence = 2
	tampered.Phase = "Validating"
	tampered.Reason = "AuthorizationValidated"
	if _, err = db.SyncNodeOperations(ctx, cluster.ID, protocol.KeyID(agentPublic), "tamper", protocol.OperationSync{Reports: []protocol.OperationReport{tampered}}, requestID); !errors.Is(err, store.ErrConflict) {
		t.Fatal("audited event history rewritten")
	}
	for _, phase := range []string{"Validating", "SafetyChecking", "Succeeded"} {
		status.Sequence++
		status.Phase = phase
		status.Reason = "Test" + phase
		status.Events = append(status.Events, protocol.PhaseEvent{Sequence: status.Sequence, Phase: phase, Reason: status.Reason, Time: metav1.Now()})
	}
	done, err := db.SyncNodeOperations(ctx, cluster.ID, protocol.KeyID(agentPublic), "complete", protocol.OperationSync{Reports: []protocol.OperationReport{status}}, requestID)
	if err != nil || len(done.Commands) != 0 || done.Acknowledged[op.ID] != 4 {
		t.Fatalf("completion did not release central capacity: %v", err)
	}
	if _, err = db.SyncNodeOperations(ctx, cluster.ID, protocol.KeyID(agentPublic), "complete-again", protocol.OperationSync{Reports: []protocol.OperationReport{status}}, requestID); err != nil {
		t.Fatal(err)
	}
	// A protocol-valid late recovery report must reopen the same durable
	// reservation that a terminal success released.
	now = time.Now().UTC()
	drainCatalog := &protocol.MaintenancePolicyCatalog{ObservedAt: now, Capabilities: &protocol.OperatorCapabilities{ObservedAt: now, NodeMaintenance: true}, Items: []protocol.MaintenancePolicyCatalogEntry{{Policy: policy, AllowedActions: []string{protocol.DrainAndVerify, protocol.ValidateOnly}}}}
	if err = db.AcceptReport(ctx, cluster.ID, protocol.KeyID(agentPublic), "inventory-drain", protocol.Report{ClusterUID: e.ClusterUID, Version: 2, ObservedAt: now, KubernetesVersion: "v1.37.0", Nodes: []protocol.Node{{UID: "worker-uid", Name: "worker1", Ready: true}}, PolicyCatalog: drainCatalog}); err != nil {
		t.Fatalf("refresh policy catalog for recovery test: %v", err)
	}
	drainInput := protocol.MaintenanceRequest{OperationID: store.NewID(), NodeName: "worker1", NodeUID: "worker-uid", Policy: policy, Action: protocol.DrainAndVerify}
	drainOp, err := db.CreateNodeOperation(ctx, org.ID, cluster.ID, drainInput, hubPrivate, "test", requestID)
	if err != nil {
		t.Fatalf("create drain operation for terminal recovery test: %v", err)
	}
	drainStatus := protocol.OperationReport{OperationID: drainOp.ID, Phase: "Succeeded", Reason: "TestSucceeded"}
	for _, phase := range []string{"Pending", "Validating", "SafetyChecking", "Cordoning", "Draining", "VerifyingNode", "VerifyingWorkloads", "Uncordoning", "Succeeded"} {
		drainStatus.Sequence++
		drainStatus.Phase = phase
		reason := "Test" + phase
		if phase == "Succeeded" {
			reason = drainStatus.Reason
		}
		drainStatus.Reason = reason
		drainStatus.Events = append(drainStatus.Events, protocol.PhaseEvent{Sequence: drainStatus.Sequence, Phase: phase, Reason: reason, Time: metav1.NewTime(time.Now().UTC())})
	}
	if _, err = db.SyncNodeOperations(ctx, cluster.ID, protocol.KeyID(agentPublic), "drain-success", protocol.OperationSync{Reports: []protocol.OperationReport{drainStatus}}, requestID); err != nil {
		t.Fatalf("record initial drain success: %v", err)
	}
	lateRecovery := drainStatus
	lateRecovery.Events = append([]protocol.PhaseEvent(nil), drainStatus.Events...)
	lateRecovery.Sequence++
	lateRecovery.Phase = "RecoveryRequired"
	lateRecovery.Reason = "TerminalRecoveryIncomplete"
	lateRecovery.Events = append(lateRecovery.Events, protocol.PhaseEvent{Sequence: lateRecovery.Sequence, Phase: lateRecovery.Phase, Reason: lateRecovery.Reason, Time: metav1.NewTime(time.Now().UTC())})
	if _, err = db.SyncNodeOperations(ctx, cluster.ID, protocol.KeyID(agentPublic), "late-terminal-recovery", protocol.OperationSync{Reports: []protocol.OperationReport{lateRecovery}}, requestID); err != nil {
		t.Fatalf("protocol-authorized terminal recovery transition was rejected: %v", err)
	}
	var phase string
	var reservationActive bool
	if err = db.Pool.QueryRow(ctx, `SELECT o.phase,r.released_at IS NULL FROM node_operations o JOIN operation_reservations r ON r.operation_id=o.id WHERE o.id=$1`, drainOp.ID).Scan(&phase, &reservationActive); err != nil || phase != "RecoveryRequired" || !reservationActive {
		t.Fatalf("terminal recovery did not restore its durable fence: phase=%s reservationActive=%t err=%v", phase, reservationActive, err)
	}
	blockedLifecycle, err := db.LabLifecycleStatus(ctx, org.ID, cluster.ID)
	if err != nil || blockedLifecycle.UnsafeOperations == 0 || blockedLifecycle.UnreleasedReservations == 0 {
		t.Fatalf("recovery state did not block lifecycle stop: %+v err=%v", blockedLifecycle, err)
	}
	recovered := lateRecovery
	recovered.Events = append([]protocol.PhaseEvent(nil), lateRecovery.Events...)
	for _, recoveryPhase := range []string{"VerifyingNode", "VerifyingWorkloads", "Uncordoning", "Succeeded"} {
		recovered.Sequence++
		recovered.Phase = recoveryPhase
		recovered.Reason = "Recovered" + recoveryPhase
		recovered.Events = append(recovered.Events, protocol.PhaseEvent{Sequence: recovered.Sequence, Phase: recoveryPhase, Reason: recovered.Reason, Time: metav1.NewTime(time.Now().UTC())})
	}
	if _, err = db.SyncNodeOperations(ctx, cluster.ID, protocol.KeyID(agentPublic), "terminal-recovery-complete", protocol.OperationSync{Reports: []protocol.OperationReport{recovered}}, requestID); err != nil {
		t.Fatalf("recovered operation did not complete: %v", err)
	}
	if err = db.Pool.QueryRow(ctx, `SELECT o.phase,r.released_at IS NULL FROM node_operations o JOIN operation_reservations r ON r.operation_id=o.id WHERE o.id=$1`, drainOp.ID).Scan(&phase, &reservationActive); err != nil || phase != "Succeeded" || reservationActive {
		t.Fatalf("completed recovery did not release its reservation: phase=%s reservationActive=%t err=%v", phase, reservationActive, err)
	}
	// A second Store uses an independent connection pool to exercise the same
	// durable cluster-row lock used by operation admission.
	db2, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	raceInput := input
	raceInput.OperationID = store.NewID()
	raceErr := make(chan error, 1)
	stopResult := make(chan store.LabLifecycle, 1)
	stopErr := make(chan error, 1)
	start := make(chan struct{})
	go func() {
		<-start
		_, e := db.CreateNodeOperation(ctx, org.ID, cluster.ID, raceInput, hubPrivate, "race-test", requestID)
		raceErr <- e
	}()
	go func() {
		<-start
		v, e := db2.RequestLabStop(ctx, org.ID, cluster.ID, "race-test", requestID)
		stopResult <- v
		stopErr <- e
	}()
	close(start)
	createErr := <-raceErr
	stopState := <-stopResult
	if e := <-stopErr; e != nil {
		t.Fatal(e)
	}
	if createErr != nil && !errors.Is(createErr, store.ErrLabBarrier) {
		t.Fatalf("concurrent operation admission failed unexpectedly: %v", createErr)
	}
	if createErr == nil && (stopState.State != store.LabDraining || stopState.CanStop) {
		t.Fatalf("shutdown crossed an admitted operation: state=%+v", stopState)
	}
	if errors.Is(createErr, store.ErrLabBarrier) && stopState.State != store.LabReadyToStop {
		t.Fatalf("stop barrier did not fence admission: state=%+v", stopState)
	}
	dbRestarted, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer dbRestarted.Close()
	restartedState, err := dbRestarted.LabLifecycleStatus(ctx, org.ID, cluster.ID)
	if err != nil || restartedState.State != stopState.State {
		t.Fatalf("lifecycle barrier did not survive controller restart: before=%s after=%s err=%v", stopState.State, restartedState.State, err)
	}
	if createErr == nil {
		raceReport := protocol.OperationReport{OperationID: raceInput.OperationID, Sequence: 4, Phase: "Succeeded", Reason: "RaceTestSucceeded"}
		for i, phase := range []string{"Pending", "Validating", "SafetyChecking", "Succeeded"} {
			raceReport.Events = append(raceReport.Events, protocol.PhaseEvent{Sequence: int64(i + 1), Phase: phase, Reason: "RaceTest" + phase, Time: metav1.Now()})
		}
		if !raceReport.ValidateForAction(input.Action) || !raceReport.ValidateAt(time.Now(), protocol.ClockSkew) {
			t.Fatal("test terminal report is not protocol-valid")
		}
		if _, err = db.SyncNodeOperations(ctx, cluster.ID, protocol.KeyID(agentPublic), "race-finish", protocol.OperationSync{Reports: []protocol.OperationReport{raceReport}}, requestID); err != nil {
			t.Fatalf("admitted operation could not finish while draining state=%s: %v", stopState.State, err)
		}
	}
	// Duplicate stop requests on independent controller pools converge on one
	// durable barrier; a stopped state is not committed until VM verification.
	var wg sync.WaitGroup
	stopErrors := make(chan error, 2)
	for _, controller := range []*store.Store{db, db2} {
		wg.Add(1)
		go func(s *store.Store) {
			defer wg.Done()
			_, e := s.RequestLabStop(ctx, org.ID, cluster.ID, "race-test", requestID)
			stopErrors <- e
		}(controller)
	}
	wg.Wait()
	close(stopErrors)
	for e := range stopErrors {
		if e != nil {
			t.Fatal(e)
		}
	}
	ready, err := db.LabLifecycleStatus(ctx, org.ID, cluster.ID)
	if err != nil || ready.State != store.LabReadyToStop || !ready.CanStop || ready.UnreleasedReservations != 0 {
		t.Fatalf("terminal reports/reservations did not safely drain: %+v err=%v", ready, err)
	}
	markErrors := make(chan error, 2)
	for _, controller := range []*store.Store{db, db2} {
		wg.Add(1)
		go func(s *store.Store) {
			defer wg.Done()
			_, e := s.MarkLabStopping(ctx, org.ID, cluster.ID, "race-test", requestID)
			markErrors <- e
		}(controller)
	}
	wg.Wait()
	close(markErrors)
	var marked, conflicted int
	for e := range markErrors {
		if e == nil {
			marked++
		} else if errors.Is(e, store.ErrConflict) {
			conflicted++
		} else {
			t.Fatal(e)
		}
	}
	if marked != 1 || conflicted != 1 {
		t.Fatalf("concurrent stop claim had %d winners and %d conflicts", marked, conflicted)
	}
	lateRecovery = protocol.OperationReport{OperationID: raceInput.OperationID, Sequence: 5, Phase: "RecoveryRequired", Reason: "TerminalRecoveryIncomplete"}
	for i, phase := range []string{"Pending", "Validating", "SafetyChecking", "Succeeded", "RecoveryRequired"} {
		reason := "RaceTest" + phase
		if phase == "RecoveryRequired" {
			reason = lateRecovery.Reason
		}
		lateRecovery.Events = append(lateRecovery.Events, protocol.PhaseEvent{Sequence: int64(i + 1), Phase: phase, Reason: reason, Time: metav1.Now()})
	}
	if _, err = db2.SyncNodeOperations(ctx, cluster.ID, protocol.KeyID(agentPublic), "late-recovery-after-stop-claim",
		protocol.OperationSync{Reports: []protocol.OperationReport{lateRecovery}}, requestID); !errors.Is(err, store.ErrLabBarrier) {
		t.Fatalf("late recovery report crossed an active stop claim: %v", err)
	}
	if _, err = db.CompleteLabStop(ctx, org.ID, cluster.ID, "race-test", requestID); err != nil {
		t.Fatal(err)
	}
	blocked := input
	blocked.OperationID = store.NewID()
	if _, err = db2.CreateNodeOperation(ctx, org.ID, cluster.ID, blocked, hubPrivate, "race-test", requestID); !errors.Is(err, store.ErrLabBarrier) {
		t.Fatalf("stopped lab admitted maintenance: %v", err)
	}
	if _, err = db2.BeginLabStart(ctx, org.ID, cluster.ID, "race-test", requestID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.CompleteLabStart(ctx, org.ID, cluster.ID, "race-test", requestID); err != nil {
		t.Fatal(err)
	}
	started, err := db.LabLifecycleStatus(ctx, org.ID, cluster.ID)
	if err != nil || started.State != store.LabRunning {
		t.Fatalf("lab did not return to running after verified-start transition: %+v %v", started, err)
	}
	snapshots, err := db.ListNodeOperations(ctx, org.ID, cluster.ID, 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, snapshot := range snapshots {
		validateResponse(snapshot)
	}
	var auditCount int
	if err = db.Pool.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE resource_id=$1 AND action LIKE 'maintenance.%'", op.ID).Scan(&auditCount); err != nil || auditCount != 5 {
		t.Fatalf("duplicate or missing audit transitions: %d %v", auditCount, err)
	}
	if _, err = db.ListNodeOperations(ctx, store.NewID(), cluster.ID, 100, 0); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("cross-tenant operation access")
	}
	next, err := db.CreateNodeOperation(ctx, org.ID, cluster.ID, second, hubPrivate, "test", requestID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Pool.Exec(ctx, "UPDATE node_operations SET expires_at=now()-interval '1 minute' WHERE id=$1", next.ID); err != nil {
		t.Fatal(err)
	}
	response, err := db.SyncNodeOperations(ctx, cluster.ID, protocol.KeyID(agentPublic), "expired-undelivered", protocol.OperationSync{}, requestID)
	if err != nil || len(response.Commands) != 0 {
		t.Fatal("expired undelivered command offered")
	}
	// An offered command has unknown acceptance until local status arrives; expiry cannot release it.
	third := input
	third.OperationID = store.NewID()
	held, err := db.CreateNodeOperation(ctx, org.ID, cluster.ID, third, hubPrivate, "test", requestID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.SyncNodeOperations(ctx, cluster.ID, protocol.KeyID(agentPublic), "offered", protocol.OperationSync{}, requestID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Pool.Exec(ctx, "UPDATE node_operations SET expires_at=now()-interval '1 minute' WHERE id=$1", held.ID); err != nil {
		t.Fatal(err)
	}
	queueReport := protocol.OperationReport{
		OperationID: held.ID, Sequence: 1, Phase: "RecoveryRequired", Reason: "TestRecoveryRequired",
		Events: []protocol.PhaseEvent{{Sequence: 1, Phase: "RecoveryRequired", Reason: "TestRecoveryRequired", Time: metav1.Now()}},
	}
	queueStatus, err := json.Marshal(queueReport)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Pool.Exec(ctx, "UPDATE node_operations SET phase='RecoveryRequired',sequence=1,status=$2 WHERE id=$1", held.ID, queueStatus); err != nil {
		t.Fatal(err)
	}
	attention, err := db.ListOrganizationOperations(ctx, org.ID, "RecoveryRequired", 100, 0)
	if err != nil || len(attention) != 1 || attention[0].ID != held.ID || attention[0].Evidence == nil || attention[0].Status == nil {
		t.Fatalf("organization recovery queue omitted durable evidence: items=%+v err=%v", attention, err)
	}
	otherTenant, err := db.ListOrganizationOperations(ctx, store.NewID(), "RecoveryRequired", 100, 0)
	if err != nil || len(otherTenant) != 0 {
		t.Fatalf("recovery queue crossed organization boundary: items=%+v err=%v", otherTenant, err)
	}
	if _, err = db.ListOrganizationOperations(ctx, org.ID, "Executing", 100, 0); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("unlisted operation phase accepted by review queue: %v", err)
	}
	fourth := input
	fourth.OperationID = store.NewID()
	if _, err = db.CreateNodeOperation(ctx, org.ID, cluster.ID, fourth, hubPrivate, "test", requestID); !errors.Is(err, store.ErrConflict) {
		t.Fatal("expiry released potentially disrupted capacity")
	}
	blockedStop, err := db.RequestLabStop(ctx, org.ID, cluster.ID, "test", requestID)
	if err != nil || blockedStop.State != store.LabDraining || blockedStop.CanStop || blockedStop.UnsafeOperations < 1 {
		t.Fatalf("recovery-required operation did not retain the stop fence: %+v %v", blockedStop, err)
	}
	if _, err = db.Pool.Exec(ctx, `UPDATE node_operations SET phase='Succeeded',terminal_at=now(),sequence=0,status='{}'::jsonb WHERE id=$1`, held.ID); err != nil {
		t.Fatal(err)
	}
	incomplete, err := db2.RequestLabStop(ctx, org.ID, cluster.ID, "test", requestID)
	if err != nil || incomplete.CanStop || !contains(incomplete.Blockers, "terminal_operation_report_not_finalized") || incomplete.UnreleasedReservations == 0 {
		t.Fatalf("incomplete terminal evidence/reservation did not block shutdown: %+v %v", incomplete, err)
	}
}

func contains(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}
