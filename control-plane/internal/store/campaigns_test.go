package store_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/jackc/pgx/v5"
	"io"
	"kordex.local/control-plane/internal/httpapi"
	"log/slog"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"kordex.local/api/campaign"
	"kordex.local/api/protocol"
	"kordex.local/control-plane/internal/store"
)

type campaignLab struct {
	t        *testing.T
	ctx      context.Context
	db       *store.Store
	org      string
	clusters []string
	keys     []string
	hub      ed25519.PrivateKey
	spec     campaign.Spec
}

func newCampaignLab(t *testing.T, n int) *campaignLab {
	t.Helper()
	dsn := os.Getenv("KORDEX_TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("CI") == "true" {
			t.Fatal("database required")
		}
		t.Skip("disposable database required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	admin, e := store.Open(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	schema := "campaign_test_" + strings.ReplaceAll(store.NewID(), "-", "")
	if _, e = admin.Pool.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); e != nil {
		admin.Close()
		t.Fatal(e)
	}
	parsed, e := url.Parse(dsn)
	if e != nil {
		t.Fatal(e)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	db, e := store.Open(ctx, parsed.String())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		db.Close()
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, e := admin.Pool.Exec(cleanup, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE"); e != nil {
			t.Error(e)
		}
		admin.Close()
	})
	if e = db.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	org, e := db.CreateOrganization(ctx, "campaign-"+store.NewID(), "creator", store.NewID())
	if e != nil {
		t.Fatal(e)
	}
	l := &campaignLab{t: t, ctx: ctx, db: db, org: org.ID, hub: key}
	t.Cleanup(func() {
		_, e := db.Pool.Exec(context.Background(), "UPDATE campaigns SET phase='Cancelled' WHERE organization_id=$1", org.ID)
		if e != nil {
			t.Error(e)
		}
	})
	site, e := db.CreateSite(ctx, org.ID, "lab", "local", "creator", store.NewID())
	if e != nil {
		t.Fatal(e)
	}
	fleet, e := db.CreateFleet(ctx, org.ID, "fleet", "creator", store.NewID())
	if e != nil {
		t.Fatal(e)
	}
	l.spec = campaign.Spec{Name: "rollout", Action: protocol.ValidateOnly, ApprovalMode: "AllStages", Selection: campaign.Selection{NodeSelector: "pool=worker"}, Windows: []campaign.Window{{Start: time.Now().UTC().Add(-time.Minute), End: time.Now().UTC().Add(time.Hour), TimeZone: "UTC"}}, Stages: []campaign.Stage{{Name: "Canary", Count: 1, BatchSize: 1}, {Name: "SmallBatch", Count: 1, BatchSize: 2}, {Name: "Expanded", Count: 1, BatchSize: 2}, {Name: "Remaining", BatchSize: 2}}}
	for i := 0; i < n; i++ {
		c, e := db.CreateCluster(ctx, store.Cluster{OrganizationID: org.ID, FleetID: fleet.ID, SiteID: site.ID, Name: fmt.Sprintf("cluster-%d", i), Provider: "self-managed"}, "creator", store.NewID())
		if e != nil {
			t.Fatal(e)
		}
		token, e := db.IssueEnrollment(ctx, org.ID, c.ID, "creator", store.NewID())
		if e != nil {
			t.Fatal(e)
		}
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		en := protocol.Enrollment{ClusterID: c.ID, ClusterUID: "kube-" + c.ID, Token: token.Token, PublicKey: protocol.EncodeKey(pub)}
		en.Proof = protocol.Proof(priv, protocol.EnrollmentMessage(en))
		if _, e = db.EnrollAgent(ctx, en, store.NewID()); e != nil {
			t.Fatal(e)
		}
		if e = db.AcceptReport(ctx, c.ID, protocol.KeyID(pub), store.NewID(), protocol.Report{ClusterUID: en.ClusterUID, Version: 1, ObservedAt: time.Now(), KubernetesVersion: "v1.37.0", Nodes: []protocol.Node{{Name: "worker", UID: "node-" + c.ID, Ready: true, Labels: map[string]string{"pool": "worker"}}}}); e != nil {
			t.Fatal(e)
		}
		l.clusters = append(l.clusters, c.ID)
		l.keys = append(l.keys, protocol.KeyID(pub))
		l.spec.Selection.ClusterIDs = append(l.spec.Selection.ClusterIDs, c.ID)
		l.spec.Policies = append(l.spec.Policies, campaign.PolicyBinding{ClusterID: c.ID, Policy: protocol.PolicyReference{Name: "safe", UID: "policy-" + c.ID, Generation: 1}})
	}
	return l
}
func (l *campaignLab) create() store.Campaign {
	l.t.Helper()
	c, e := l.db.CreateCampaign(l.ctx, l.org, store.NewID(), l.spec, "creator", store.NewID())
	if e != nil {
		l.t.Fatal(e)
	}
	c, e = l.db.StartCampaign(l.ctx, l.org, c.ID, c.Revision, "creator", store.NewID())
	if e != nil {
		l.t.Fatal(e)
	}
	return c
}
func (l *campaignLab) get(id string) store.Campaign {
	l.t.Helper()
	c, e := l.db.GetCampaign(l.ctx, l.org, id)
	if e != nil {
		l.t.Fatal(e)
	}
	return c
}
func (l *campaignLab) control(c store.Campaign, action, actor, role string) store.Campaign {
	l.t.Helper()
	c, e := l.db.ControlCampaign(l.ctx, l.org, c.ID, action, store.CampaignControl{Revision: c.Revision, AcknowledgedFailures: c.Progress.FailedAttempts}, actor, role, store.NewID(), l.hub)
	if e != nil {
		l.t.Fatal(action, e)
	}
	return c
}
func (l *campaignLab) tick() store.ScheduleResult {
	l.t.Helper()
	r, e := l.db.ScheduleOnce(l.ctx, l.hub, "test-worker", 0)
	if e != nil {
		l.t.Fatal(e)
	}
	return r
}
func (l *campaignLab) finish(id, phase, reason string) {
	l.t.Helper()
	var cluster string
	if e := l.db.Pool.QueryRow(l.ctx, "SELECT cluster_id FROM node_operations WHERE id=$1", id).Scan(&cluster); e != nil {
		l.t.Fatal(e)
	}
	idx := 0
	for i, c := range l.clusters {
		if c == cluster {
			idx = i
		}
	}
	if _, e := l.db.SyncNodeOperations(l.ctx, cluster, l.keys[idx], store.NewID(), protocol.OperationSync{}, store.NewID()); e != nil {
		l.t.Fatal(e)
	}
	report := protocol.OperationReport{OperationID: id, Sequence: 1, Phase: phase, Reason: reason, Events: []protocol.PhaseEvent{{Sequence: 1, Phase: phase, Reason: reason, Time: metav1.Now()}}}
	if _, e := l.db.SyncNodeOperations(l.ctx, cluster, l.keys[idx], store.NewID(), protocol.OperationSync{Reports: []protocol.OperationReport{report}}, store.NewID()); e != nil {
		l.t.Fatal(e)
	}
}
func TestCampaignApprovalStagesAndIsolation(t *testing.T) {
	l := newCampaignLab(t, 4)
	c := l.create()
	if c.Phase != "AwaitingApproval" {
		t.Fatal(c.Phase)
	}
	if len(l.tick().Operations) != 0 {
		t.Fatal("unapproved work issued")
	}
	if _, e := l.db.ControlCampaign(l.ctx, l.org, c.ID, "approve", store.CampaignControl{Revision: c.Revision}, "creator", "administrator", store.NewID(), l.hub); !errors.Is(e, store.ErrForbidden) {
		t.Fatal("creator approved own plan", e)
	}
	if _, e := l.db.GetCampaign(l.ctx, store.NewID(), c.ID); !errors.Is(e, store.ErrNotFound) {
		t.Fatal("cross-tenant read", e)
	}
	for stage := 0; stage < 4; stage++ {
		c = l.get(c.ID)
		if c.Stage != stage || c.Phase != "AwaitingApproval" {
			t.Fatalf("stage gate: %+v", c)
		}
		c = l.control(c, "approve", "reviewer", "approver")
		r := l.tick()
		if len(r.Operations) != 1 {
			t.Fatalf("stage %d no operation: %+v", stage, r)
		}
		var encoded []byte
		if e := l.db.Pool.QueryRow(l.ctx, "SELECT command FROM node_operations WHERE id=$1", r.Operations[0]).Scan(&encoded); e != nil {
			t.Fatal(e)
		}
		l.finish(r.Operations[0], "Succeeded", "Verified")
		l.tick()
	}
	c = l.get(c.ID)
	if c.Phase != "Succeeded" || c.Progress.Succeeded != 4 {
		t.Fatalf("not complete: %+v", c)
	}
	approvals, e := l.db.ListCampaignApprovals(l.ctx, l.org, c.ID, 100, 0)
	if e != nil || len(approvals) != 4 {
		t.Fatal("missing approvals", e)
	}
	events, e := l.db.ListCampaignEvents(l.ctx, l.org, c.ID, 500, 0)
	if e != nil || len(events) < 16 {
		t.Fatal("missing durable history", e)
	}
}
func TestConcurrentCampaignAdmissionPauseCancelAndCapacity(t *testing.T) {
	l := newCampaignLab(t, 3)
	l.spec.ApprovalMode = "None"
	l.spec.Stages[0].Count = 3
	l.spec.Stages[0].BatchSize = 3
	c := l.create()
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Go(func() { _, e := l.db.ScheduleOnce(l.ctx, l.hub, store.NewID(), 0); errs <- e })
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	targets, e := l.db.ListCampaignTargets(l.ctx, l.org, c.ID, 100, 0)
	if e != nil {
		t.Fatal(e)
	}
	active := 0
	for _, target := range targets {
		if target.State == "Active" {
			active++
		}
	}
	if active != 1 {
		t.Fatal("global budget over-admitted", active)
	}
	c = l.control(l.get(c.ID), "pause", "operator", "operator")
	if len(l.tick().Operations) != 0 {
		t.Fatal("pause admitted work")
	}
	var op, cluster string
	if e = l.db.Pool.QueryRow(l.ctx, "SELECT id,cluster_id FROM node_operations WHERE campaign_id=$1", c.ID).Scan(&op, &cluster); e != nil {
		t.Fatal(e)
	}
	idx := 0
	for i, v := range l.clusters {
		if v == cluster {
			idx = i
		}
	}
	if _, e = l.db.SyncNodeOperations(l.ctx, cluster, l.keys[idx], store.NewID(), protocol.OperationSync{}, store.NewID()); e != nil {
		t.Fatal(e)
	}
	c = l.control(l.get(c.ID), "cancel", "operator", "operator")
	if c.Phase != "Cancelling" {
		t.Fatal("cancel released uncertain delivery")
	}
	response, e := l.db.SyncNodeOperations(l.ctx, cluster, l.keys[idx], store.NewID(), protocol.OperationSync{}, store.NewID())
	if e != nil || len(response.Controls) != 1 {
		t.Fatal("missing durable cancellation", e)
	}
	pub := l.hub.Public().(ed25519.PublicKey)
	if e = response.Controls[0].Verify(map[string]ed25519.PublicKey{protocol.KeyID(pub): pub}, op, cluster, response.Commands[0].Digest(), time.Now()); e != nil {
		t.Fatal(e)
	}
	l.tick()
	if l.get(c.ID).Phase != "Cancelling" {
		t.Fatal("unacknowledged cancel finalized")
	}
	l.finish(op, "Cancelled", "CancelledByHub")
	l.tick()
	if l.get(c.ID).Phase != "Cancelled" {
		t.Fatal("cancel did not finish")
	}
}
func TestCampaignFailureGateRetryAndRevision(t *testing.T) {
	l := newCampaignLab(t, 2)
	l.spec.ApprovalMode = "None"
	l.spec.Retry = campaign.RetryPolicy{MaxRetries: 1, BackoffSeconds: 1, Reasons: []string{"PDBBlocked"}}
	c := l.create()
	r := l.tick()
	if len(r.Operations) != 1 {
		t.Fatal("no canary")
	}
	l.finish(r.Operations[0], "Failed", "PDBBlocked")
	l.tick()
	c = l.get(c.ID)
	if c.Phase != "Paused" || c.Reason != "FailureThresholdBreached" {
		t.Fatalf("failure advanced: %+v", c)
	}
	if _, e := l.db.ControlCampaign(l.ctx, l.org, c.ID, "resume", store.CampaignControl{Revision: c.Revision, AcknowledgedFailures: 1}, "operator", "operator", store.NewID(), l.hub); !errors.Is(e, store.ErrForbidden) {
		t.Fatal("operator bypassed failure gate", e)
	}
	stale := c.Revision
	c = l.control(c, "resume", "reviewer", "approver")
	if _, e := l.db.ControlCampaign(l.ctx, l.org, c.ID, "pause", store.CampaignControl{Revision: stale}, "operator", "operator", store.NewID(), l.hub); !errors.Is(e, store.ErrConflict) {
		t.Fatal("stale revision accepted", e)
	}
	if _, e := l.db.Pool.Exec(l.ctx, "UPDATE campaign_targets SET next_attempt_at=now() WHERE campaign_id=$1", c.ID); e != nil {
		t.Fatal(e)
	}
	r = l.tick()
	if len(r.Operations) != 1 {
		t.Fatal("retry absent")
	}
	if r.Operations[0] == "" {
		t.Fatal("missing attempt identity")
	}
	l.finish(r.Operations[0], "Succeeded", "Verified")
	l.tick()
	c = l.get(c.ID)
	if c.Stage != 1 {
		t.Fatal("retry did not unblock stage")
	}
}
func TestCampaignWindowAndSnapshotVeto(t *testing.T) {
	l := newCampaignLab(t, 1)
	l.spec.ApprovalMode = "None"
	l.spec.Windows[0].Start = time.Now().UTC().Add(time.Hour)
	l.spec.Windows[0].End = time.Now().UTC().Add(2 * time.Hour)
	c := l.create()
	if len(l.tick().Operations) != 0 || l.get(c.ID).Reason != "WaitingForWindow" {
		t.Fatal("outside window work issued")
	}
	c = l.control(l.get(c.ID), "cancel", "operator", "operator")
	if c.Phase != "Cancelled" {
		t.Fatal("empty campaign did not cancel")
	}
	l.spec.Windows[0].Start = time.Now().UTC().Add(-time.Minute)
	l.spec.Windows[0].End = time.Now().UTC().Add(time.Hour)
	c = l.create()
	if _, e := l.db.Pool.Exec(l.ctx, "UPDATE nodes SET inventory=jsonb_set(inventory,'{labels}','{\"pool\":\"other\"}') WHERE cluster_id=$1", l.clusters[0]); e != nil {
		t.Fatal(e)
	}
	if len(l.tick().Operations) != 0 || l.get(c.ID).Reason != "TargetSnapshotChanged" {
		t.Fatal("changed selector target admitted")
	}
}

func TestCampaignHTTPAuthorizationAndContract(t *testing.T) {
	l := newCampaignLab(t, 2)
	for _, role := range []string{"viewer", "operator", "approver", "administrator"} {
		if e := l.db.SetMembership(l.ctx, l.org, role, role, "test", store.NewID()); e != nil {
			t.Fatal(e)
		}
	}
	doc, e := openapi3.NewLoader().LoadFromFile("../../../api/openapi/v1.json")
	if e != nil {
		t.Fatal(e)
	}
	call := func(role, method, path string, input any, status int, schema string) []byte {
		t.Helper()
		body, e := json.Marshal(input)
		if e != nil {
			t.Fatal(e)
		}
		handler := httpapi.NewWithOptions(l.db, "", "Kordex", slog.New(slog.NewJSONHandler(io.Discard, nil)), httpapi.Options{Verifier: subjectVerifier{Subject: role}, MaintenanceKey: l.hub})
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer viewer-token")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != status {
			t.Fatalf("%s %s role=%s: %d %s", method, path, role, w.Code, w.Body.String())
		}
		if schema != "" {
			var v any
			if e = json.Unmarshal(w.Body.Bytes(), &v); e != nil {
				t.Fatal(e)
			}
			if e = doc.Components.Schemas[schema].Value.VisitJSON(v); e != nil {
				t.Fatal(e)
			}
		}
		return w.Body.Bytes()
	}
	base := "/v1/organizations/" + l.org
	id := store.NewID()
	input := map[string]any{"id": id, "spec": l.spec}
	call("viewer", "POST", base+"/campaigns", input, 403, "Error")
	call("approver", "POST", base+"/campaigns", input, 403, "Error")
	var c store.Campaign
	data := call("operator", "POST", base+"/campaigns", input, 201, "Campaign")
	if e = json.Unmarshal(data, &c); e != nil {
		t.Fatal(e)
	}
	call("operator", "POST", base+"/campaigns", input, 201, "Campaign")
	data = call("operator", "POST", base+"/campaigns/"+id+"/start", map[string]any{"revision": c.Revision}, 200, "Campaign")
	if e = json.Unmarshal(data, &c); e != nil {
		t.Fatal(e)
	}
	call("viewer", "HEAD", base+"/campaigns/"+id, nil, 200, "Campaign")
	call("operator", "POST", base+"/campaigns/"+id+"/approve", map[string]any{"revision": c.Revision}, 403, "Error")
	call("approver", "POST", base+"/campaigns/"+id+"/approve", map[string]any{"revision": c.Revision}, 200, "Campaign")
	for _, suffix := range []struct{ path, schema string }{{"/campaigns", "CampaignPage"}, {"/campaigns/" + id + "/targets", "CampaignTargetPage"}, {"/campaigns/" + id + "/events", "CampaignEventPage"}, {"/campaigns/" + id + "/approvals", "CampaignApprovalPage"}, {"/concurrency-policy", "ConcurrencyPolicy"}} {
		call("viewer", "GET", base+suffix.path, nil, 200, suffix.schema)
	}
	call("operator", "PUT", base+"/concurrency-policy", map[string]any{"revision": 1, "limits": campaign.DefaultLimits()}, 403, "Error")
	call("viewer", "GET", "/v1/organizations/"+store.NewID()+"/campaigns/"+id, nil, 403, "Error")
}

func TestCampaignManualBudgetAndUnknownSiteHealth(t *testing.T) {
	l := newCampaignLab(t, 3)
	l.spec.ApprovalMode = "None"
	l.spec.Selection.ClusterIDs = l.spec.Selection.ClusterIDs[1:]
	manual := protocol.MaintenanceRequest{OperationID: store.NewID(), NodeName: "worker", NodeUID: "node-" + l.clusters[0], Action: protocol.ValidateOnly, Policy: l.spec.Policies[0].Policy}
	op, e := l.db.CreateNodeOperation(l.ctx, l.org, l.clusters[0], manual, l.hub, "operator", store.NewID())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = l.db.SyncNodeOperations(l.ctx, l.clusters[0], l.keys[0], store.NewID(), protocol.OperationSync{}, store.NewID()); e != nil {
		t.Fatal(e)
	}
	if _, e = l.db.Pool.Exec(l.ctx, "UPDATE node_operations SET expires_at=now()-interval '1 minute' WHERE id=$1", op.ID); e != nil {
		t.Fatal(e)
	}
	c := l.create()
	if len(l.tick().Operations) != 0 {
		t.Fatal("campaign bypassed offered manual reservation after expiry")
	}
	if e = l.db.CancelNodeOperation(l.ctx, l.org, l.clusters[0], op.ID, l.hub, "operator", store.NewID()); e != nil {
		t.Fatal(e)
	}
	if len(l.tick().Operations) != 0 {
		t.Fatal("cancel request released manual capacity")
	}
	l.finish(op.ID, "Cancelled", "CancelledByHub")
	if _, e = l.db.Pool.Exec(l.ctx, "UPDATE clusters SET observed_at=now()-interval '3 minutes' WHERE id=$1", l.clusters[0]); e != nil {
		t.Fatal(e)
	}
	if len(l.tick().Operations) != 0 {
		t.Fatal("unknown site health admitted work")
	}
	if _, e = l.db.Pool.Exec(l.ctx, "UPDATE clusters SET observed_at=now(),last_heartbeat_at=now() WHERE id=$1", l.clusters[0]); e != nil {
		t.Fatal(e)
	}
	if len(l.tick().Operations) != 1 {
		t.Fatal("recovered site remained blocked")
	}
	if l.get(c.ID).Progress.Active != 1 {
		t.Fatal("durable progress incorrect")
	}
}
func TestCampaignScopeBudgetsAndAtomicRollback(t *testing.T) {
	l := newCampaignLab(t, 3)
	l.spec.ApprovalMode = "None"
	l.spec.Stages[0].Count = 3
	l.spec.Stages[0].BatchSize = 3
	limits := campaign.Limits{Organization: 3, Fleet: 3, Site: 3, Cluster: 1, Node: 1, MaxUnavailablePerSite: 3}
	l.spec.Limits = limits
	// Inject a database failure after command/reservation insertion to prove admission atomicity.
	if _, e := l.db.Pool.Exec(l.ctx, `CREATE FUNCTION fail_admission() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.state='Active' THEN RAISE EXCEPTION 'injected admission failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_admission BEFORE UPDATE ON campaign_targets FOR EACH ROW EXECUTE FUNCTION fail_admission()`); e != nil {
		t.Fatal(e)
	}
	c := l.create()
	if _, e := l.db.ScheduleOnce(l.ctx, l.hub, "fault-test", 0); e == nil {
		t.Fatal("injected failure did not roll back")
	}
	var commands, reservations int
	if e := l.db.Pool.QueryRow(l.ctx, "SELECT (SELECT count(*) FROM node_operations WHERE campaign_id=$1),(SELECT count(*) FROM operation_reservations WHERE campaign_id=$1)", c.ID).Scan(&commands, &reservations); e != nil {
		t.Fatal(e)
	}
	if commands != 0 || reservations != 0 {
		t.Fatal("partial admission committed")
	}
	if _, e := l.db.Pool.Exec(l.ctx, "DROP TRIGGER fail_admission ON campaign_targets"); e != nil {
		t.Fatal(e)
	}
	limits.Fleet = 1
	p, e := l.db.SetConcurrencyPolicy(l.ctx, l.org, 1, limits, "admin", store.NewID())
	if e != nil {
		t.Fatal(e)
	}
	if len(l.tick().Operations) != 1 {
		t.Fatal("fleet budget did not admit one")
	}
	limits.Fleet = 3
	limits.Site = 1
	p, e = l.db.SetConcurrencyPolicy(l.ctx, l.org, p.Revision, limits, "admin", store.NewID())
	if e != nil {
		t.Fatal(e)
	}
	if len(l.tick().Operations) != 0 {
		t.Fatal("site budget bypassed")
	}
	limits.Site = 3
	limits.MaxUnavailablePerSite = 1
	p, e = l.db.SetConcurrencyPolicy(l.ctx, l.org, p.Revision, limits, "admin", store.NewID())
	if e != nil {
		t.Fatal(e)
	}
	if len(l.tick().Operations) != 0 {
		t.Fatal("site availability bypassed")
	}
	limits.MaxUnavailablePerSite = 3
	if _, e = l.db.SetConcurrencyPolicy(l.ctx, l.org, p.Revision, limits, "admin", store.NewID()); e != nil {
		t.Fatal(e)
	}
	if len(l.tick().Operations) != 2 {
		t.Fatal("expanded budgets did not admit remaining targets")
	}
	if l.get(c.ID).Progress.Active != 3 {
		t.Fatal("active reservations lost")
	}
}

func TestUpgradeCampaignSnapshotsExactFreshPlanDigestAcrossClusters(t *testing.T) {
	l := newCampaignLab(t, 2)
	now := time.Now().UTC()
	plan := protocol.UpgradePolicy{
		SchemaVersion: 1, ID: "ubuntu-workers", OSFamily: "debian", ExecutionBackend: "ansible-ee",
		PlaybookCatalogID:    "kordex.os-upgrade.debian.v2",
		ExecutionEnvironment: "registry.example.com/kordex/ansible-ee@sha256:" + strings.Repeat("a", 64),
		PlaybookDigest:       strings.Repeat("b", 64), CollectionsDigest: strings.Repeat("c", 64),
		Packages: []protocol.PackagePin{{Name: "curl", Version: "8.5.0-1"}}, Channel: "stable", Reboot: protocol.RebootNever,
		ExecutionTimeout: time.Minute, RebootTimeout: time.Minute, VerificationTimeout: time.Minute, MaxAttempts: 1,
	}
	digest, err := plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	l.spec.Action = protocol.UpgradePackages
	for i, clusterID := range l.clusters {
		policy := protocol.PolicyReference{Name: "ubuntu-workers", UID: "policy-" + clusterID, Generation: 1}
		l.spec.Policies[i] = campaign.PolicyBinding{ClusterID: clusterID, Policy: policy, PlanDigest: digest}
		catalog := &protocol.MaintenancePolicyCatalog{
			ObservedAt:   now,
			Capabilities: &protocol.OperatorCapabilities{ObservedAt: now, HostUpgrades: false},
			Items: []protocol.MaintenancePolicyCatalogEntry{{
				Policy: policy, NodeSelector: metav1.LabelSelector{MatchLabels: map[string]string{"pool": "worker"}},
				Upgrade: &plan, UpgradePlanDigest: digest,
			}},
		}
		report := protocol.Report{
			ClusterUID: "kube-" + clusterID, Version: 2, ObservedAt: now, KubernetesVersion: "v1.37.0",
			Nodes:         []protocol.Node{{Name: "worker", UID: "node-" + clusterID, Ready: true, Labels: map[string]string{"pool": "worker"}}},
			PolicyCatalog: catalog,
		}
		if err = l.db.AcceptReport(l.ctx, clusterID, l.keys[i], store.NewID(), report); err != nil {
			t.Fatalf("publish fresh upgrade catalog for cluster %s: %v", clusterID, err)
		}
	}
	preview, err := l.db.PreviewCampaign(l.ctx, l.org, l.spec)
	if err != nil {
		t.Fatal(err)
	}
	if preview.BlockedCount != 2 || preview.Nodes[0].Reason != "LocalUpgradeExecutorUnavailable" {
		t.Fatalf("campaign did not fail closed for disabled local executor: %+v", preview.Nodes)
	}
	for i, clusterID := range l.clusters {
		catalog := &protocol.MaintenancePolicyCatalog{
			ObservedAt: now, Capabilities: &protocol.OperatorCapabilities{ObservedAt: now, HostUpgrades: true},
			Items: []protocol.MaintenancePolicyCatalogEntry{{
				Policy: l.spec.Policies[i].Policy, NodeSelector: metav1.LabelSelector{MatchLabels: map[string]string{"pool": "worker"}},
				Upgrade: &plan, UpgradePlanDigest: digest,
			}},
		}
		report := protocol.Report{ClusterUID: "kube-" + clusterID, Version: 3, ObservedAt: now.Add(time.Second), KubernetesVersion: "v1.37.0", Nodes: []protocol.Node{{Name: "worker", UID: "node-" + clusterID, Ready: true, Labels: map[string]string{"pool": "worker"}}}, PolicyCatalog: catalog}
		if err = l.db.AcceptReport(l.ctx, clusterID, l.keys[i], store.NewID(), report); err != nil {
			t.Fatalf("publish enabled executor capability for cluster %s: %v", clusterID, err)
		}
	}
	campaignRecord, err := l.db.CreateCampaign(l.ctx, l.org, store.NewID(), l.spec, "creator", store.NewID())
	if err != nil {
		t.Fatal(err)
	}
	campaignRecord, err = l.db.StartCampaign(l.ctx, l.org, campaignRecord.ID, campaignRecord.Revision, "creator", store.NewID())
	if err != nil {
		t.Fatal(err)
	}
	if campaignRecord.Progress.Total != 2 {
		t.Fatalf("snapshotted %d upgrade targets, want 2", campaignRecord.Progress.Total)
	}
	var count int
	if err = l.db.Pool.QueryRow(l.ctx, "SELECT count(*) FROM campaign_targets WHERE campaign_id=$1 AND snapshot->>'planDigest'=$2", campaignRecord.ID, digest).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("%d targets retained the exact upgrade plan digest, want 2", count)
	}
}

func TestGKECampaignRequiresFreshLocalProviderCapability(t *testing.T) {
	l := newCampaignLab(t, 1)
	clusterID := l.clusters[0]
	if _, err := l.db.Pool.Exec(l.ctx, `UPDATE clusters SET provider='gke' WHERE id=$1`, clusterID); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	plan := protocol.ProviderNodeUpgradePlan{SchemaVersion: 2, Provider: "gke", Resource: "projects/test-project/locations/us-central1-a/clusters/cluster-0/nodePools/default-pool", TargetVersion: "1.36.4-gke.100", MaxSurge: 1, Timeout: 5 * time.Minute}
	digest, err := plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	policy := protocol.PolicyReference{Name: "gke-workers", UID: "policy-gke", Generation: 1}
	l.spec.Action = protocol.UpgradeNodePool
	l.spec.Policies = []campaign.PolicyBinding{{ClusterID: clusterID, Policy: policy, PlanDigest: digest}}
	node := protocol.Node{Name: "worker", UID: "node-" + clusterID, Ready: true, Zone: "us-central1-a", ProviderID: "gce://test-project/us-central1-a/instance-1", Labels: map[string]string{"pool": "worker", "cloud.google.com/gke-nodepool": "default-pool", "topology.kubernetes.io/zone": "us-central1-a"}}
	publish := func(version int64, enabled bool) {
		catalog := &protocol.MaintenancePolicyCatalog{ObservedAt: now, Capabilities: &protocol.OperatorCapabilities{ObservedAt: now, GKENodePoolUpgrade: enabled}, Items: []protocol.MaintenancePolicyCatalogEntry{{Policy: policy, NodeSelector: metav1.LabelSelector{MatchLabels: map[string]string{"pool": "worker"}}, ProviderUpgrade: &plan, ProviderPlanDigest: digest}}}
		report := protocol.Report{ClusterUID: "kube-" + clusterID, Version: version, ObservedAt: now, KubernetesVersion: "v1.36.4-gke.100", Nodes: []protocol.Node{node}, PolicyCatalog: catalog}
		if publishErr := l.db.AcceptReport(l.ctx, clusterID, l.keys[0], store.NewID(), report); publishErr != nil {
			t.Fatalf("publish GKE report: %v", publishErr)
		}
	}
	publish(2, false)
	preview, err := l.db.PreviewCampaign(l.ctx, l.org, l.spec)
	if err != nil {
		t.Fatal(err)
	}
	if preview.BlockedCount != 1 || len(preview.Nodes) != 1 || preview.Nodes[0].Reason != "LocalGKENodePoolAdapterUnavailable" {
		t.Fatalf("campaign should be blocked by disabled local GKE adapter: %+v", preview.Nodes)
	}
	publish(3, true)
	preview, err = l.db.PreviewCampaign(l.ctx, l.org, l.spec)
	if err != nil {
		t.Fatal(err)
	}
	if !preview.StartAllowed || len(preview.Targets) != 1 {
		t.Fatalf("fresh enabled GKE capability should admit one pool target: %+v", preview)
	}
}

func TestUpgradeCampaignPausesWhenAdmissionCatalogTurnsStale(t *testing.T) {
	l := newCampaignLab(t, 1)
	clusterID := l.clusters[0]
	now := time.Now().UTC()
	plan := protocol.UpgradePolicy{
		SchemaVersion: 1, ID: "ubuntu-workers", OSFamily: "debian", ExecutionBackend: "ansible-ee",
		PlaybookCatalogID:    "kordex.os-upgrade.debian.v2",
		ExecutionEnvironment: "registry.example.com/kordex/ansible-ee@sha256:" + strings.Repeat("a", 64),
		PlaybookDigest:       strings.Repeat("b", 64), CollectionsDigest: strings.Repeat("c", 64),
		Packages: []protocol.PackagePin{{Name: "curl", Version: "8.5.0-1"}}, Channel: "stable", Reboot: protocol.RebootNever,
		ExecutionTimeout: time.Minute, RebootTimeout: time.Minute, VerificationTimeout: time.Minute, MaxAttempts: 1,
	}
	digest, err := plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	policy := protocol.PolicyReference{Name: "ubuntu-workers", UID: "policy-" + clusterID, Generation: 1}
	l.spec.Action = protocol.UpgradePackages
	l.spec.Policies[0] = campaign.PolicyBinding{ClusterID: clusterID, Policy: policy, PlanDigest: digest}
	catalog := &protocol.MaintenancePolicyCatalog{
		ObservedAt: now, Capabilities: &protocol.OperatorCapabilities{ObservedAt: now, HostUpgrades: true},
		Items: []protocol.MaintenancePolicyCatalogEntry{{
			Policy: policy, NodeSelector: metav1.LabelSelector{MatchLabels: map[string]string{"pool": "worker"}},
			Upgrade: &plan, UpgradePlanDigest: digest,
		}},
	}
	report := protocol.Report{
		ClusterUID: "kube-" + clusterID, Version: 2, ObservedAt: now, KubernetesVersion: "v1.37.0",
		Nodes:         []protocol.Node{{Name: "worker", UID: "node-" + clusterID, Ready: true, Labels: map[string]string{"pool": "worker"}}},
		PolicyCatalog: catalog,
	}
	if err = l.db.AcceptReport(l.ctx, clusterID, l.keys[0], store.NewID(), report); err != nil {
		t.Fatal(err)
	}
	c := l.create()
	if _, err = l.db.Pool.Exec(l.ctx, `UPDATE clusters SET maintenance_policy_catalog_observed_at=now()-interval '2 minutes' WHERE id=$1`, clusterID); err != nil {
		t.Fatal(err)
	}
	result := l.tick()
	if len(result.Operations) != 0 {
		t.Fatalf("stale admission evidence issued operations: %v", result.Operations)
	}
	updated := l.get(c.ID)
	if updated.Phase != "Paused" || updated.Reason != "PolicyCatalogStaleAtAdmission" {
		t.Fatalf("campaign did not pause on stale upgrade catalog: phase=%s reason=%s", updated.Phase, updated.Reason)
	}
	var operations int
	if err = l.db.Pool.QueryRow(l.ctx, `SELECT count(*) FROM node_operations WHERE campaign_id=$1`, c.ID).Scan(&operations); err != nil {
		t.Fatal(err)
	}
	if operations != 0 {
		t.Fatalf("created %d operation(s) after upgrade evidence went stale", operations)
	}
}

func TestCampaignPreviewMatchesStartWithoutPersistingTargets(t *testing.T) {
	l := newCampaignLab(t, 3)
	preview, err := l.db.PreviewCampaign(l.ctx, l.org, l.spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(preview.Targets) != 3 || len(preview.Nodes) != 3 || preview.BlockedCount != 0 || !preview.StartAllowed || preview.StageCounts[0] != 1 || preview.StageCounts[1] != 1 || preview.StageCounts[2] != 1 {
		t.Fatalf("unexpected preview assessments: targets=%d nodes=%d blocked=%d allowed=%t stages=%v", len(preview.Targets), len(preview.Nodes), preview.BlockedCount, preview.StartAllowed, preview.StageCounts)
	}
	var persisted int
	if err = l.db.Pool.QueryRow(l.ctx, "SELECT count(*) FROM campaign_targets").Scan(&persisted); err != nil {
		t.Fatal(err)
	}
	if persisted != 0 {
		t.Fatalf("read-only preview persisted %d campaign targets", persisted)
	}
	campaignRecord := l.create()
	if campaignRecord.SnapshotDigest != preview.SnapshotDigest || campaignRecord.Progress.Total != len(preview.Targets) {
		t.Fatalf("preview diverged from started campaign: preview=%s started=%s count=%d", preview.SnapshotDigest, campaignRecord.SnapshotDigest, campaignRecord.Progress.Total)
	}
}

func TestCampaignOperationsIncludeLiveClusterEvidence(t *testing.T) {
	l := newCampaignLab(t, 1)
	c := l.create()
	if result := l.tick(); len(result.Operations) != 1 {
		t.Fatalf("scheduler admitted %d operations, want one", len(result.Operations))
	}
	items, err := l.db.ListCampaignOperations(l.ctx, l.org, c.ID, 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Evidence == nil || !items[0].Evidence.InventoryFresh || !items[0].Evidence.AgentConnected || items[0].Evidence.InventoryObservedAt == nil || items[0].Evidence.AgentLastSeenAt == nil {
		t.Fatalf("fresh cluster evidence missing from operation: %+v", items)
	}
	if _, err = l.db.Pool.Exec(l.ctx, `UPDATE clusters SET observed_at=now()-interval '2 minutes',last_heartbeat_at=now()-interval '2 minutes' WHERE id=$1`, l.clusters[0]); err != nil {
		t.Fatal(err)
	}
	items, err = l.db.ListCampaignOperations(l.ctx, l.org, c.ID, 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Evidence == nil || items[0].Evidence.InventoryFresh || items[0].Evidence.AgentConnected {
		t.Fatalf("stale cluster evidence was reported as current: %+v", items)
	}
}

func TestCampaignPreviewReportsPerClusterMissingInventoryAndBlocksStart(t *testing.T) {
	l := newCampaignLab(t, 2)
	clusterID := l.clusters[0]
	report := protocol.Report{ClusterUID: "kube-" + clusterID, Version: 2, ObservedAt: time.Now(), KubernetesVersion: "v1.37.0"}
	if err := l.db.AcceptReport(l.ctx, clusterID, l.keys[0], store.NewID(), report); err != nil {
		t.Fatal(err)
	}
	preview, err := l.db.PreviewCampaign(l.ctx, l.org, l.spec)
	if err != nil {
		t.Fatal(err)
	}
	if preview.StartAllowed || preview.BlockedCount != 1 || len(preview.Targets) != 1 {
		t.Fatalf("expected one eligible target and one blocker, got allowed=%t blocked=%d targets=%d", preview.StartAllowed, preview.BlockedCount, len(preview.Targets))
	}
	var found bool
	for _, node := range preview.Nodes {
		if node.ClusterID == clusterID {
			found = node.Blocking && node.Reason == "NoNodesReported"
		}
	}
	if !found {
		t.Fatalf("preview did not report missing inventory for cluster %s: %+v", clusterID, preview.Nodes)
	}
	campaignRecord, err := l.db.CreateCampaign(l.ctx, l.org, store.NewID(), l.spec, "creator", store.NewID())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = l.db.StartCampaign(l.ctx, l.org, campaignRecord.ID, campaignRecord.Revision, "creator", store.NewID()); !errors.Is(err, store.ErrStale) {
		t.Fatalf("campaign start error = %v, want stale inventory", err)
	}
}
