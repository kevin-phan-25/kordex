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
