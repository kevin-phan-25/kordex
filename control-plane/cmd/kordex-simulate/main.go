// kordex-simulate exercises database scheduling with synthetic inventories and
// synthetic agent success reports. It never contacts Kubernetes or executes maintenance.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"kordex.local/api/campaign"
	"kordex.local/api/protocol"
	"kordex.local/control-plane/internal/store"
)

type syntheticCluster struct {
	id, key string
	report  protocol.Report
}

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	nodes := flag.Int("nodes", 4000, "synthetic nodes, 1..10000")
	clusters := flag.Int("clusters", 100, "synthetic clusters, 1..500")
	flag.Parse()
	if *nodes < 1 || *nodes > 10000 || *clusters < 1 || *clusters > 500 || *clusters > *nodes {
		return errors.New("invalid simulation size")
	}
	dsn := os.Getenv("KORDEX_SIMULATION_DATABASE_URL")
	if dsn == "" {
		return errors.New("set KORDEX_SIMULATION_DATABASE_URL to a dedicated disposable database; simulation applies migrations and retains synthetic history")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	db, e := store.Open(ctx, dsn)
	if e != nil {
		return e
	}
	defer db.Close()
	if e = db.Migrate(ctx); e != nil {
		return e
	}
	var existing bool
	if e = db.Pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM campaigns WHERE phase NOT IN ('Draft','Succeeded','Failed','Cancelled','CompletedWithFailures'))").Scan(&existing); e != nil {
		return e
	}
	if existing {
		return errors.New("simulation requires a dedicated database without runnable campaigns")
	}
	began := time.Now()
	org, e := db.CreateOrganization(ctx, "simulation-"+store.NewID(), "simulator", store.NewID())
	if e != nil {
		return e
	}
	fleet, e := db.CreateFleet(ctx, org.ID, "synthetic", "simulator", store.NewID())
	if e != nil {
		return e
	}
	sites := []string{}
	for i := 0; i < 4; i++ {
		site, e := db.CreateSite(ctx, org.ID, fmt.Sprintf("synthetic-%d", i), "simulation", "simulator", store.NewID())
		if e != nil {
			return e
		}
		sites = append(sites, site.ID)
	}
	limits := campaign.Limits{Organization: 100, Fleet: 100, Site: 25, Cluster: 1, Node: 1, MaxUnavailablePerSite: 25}
	if _, e = db.SetConcurrencyPolicy(ctx, org.ID, 1, limits, "simulator", store.NewID()); e != nil {
		return e
	}
	spec := campaign.Spec{Name: "synthetic-validate-only", Action: protocol.ValidateOnly, ApprovalMode: "None", Limits: limits, Windows: []campaign.Window{{Start: time.Now().UTC().Add(-time.Minute), End: time.Now().UTC().Add(time.Hour), TimeZone: "UTC"}}, Stages: []campaign.Stage{{Name: "Canary", Count: 1, BatchSize: 1}, {Name: "SmallBatch", Count: 5, BatchSize: 5}, {Name: "Expanded", Count: 20, BatchSize: 20}, {Name: "Remaining", BatchSize: 100}}}
	inventory := map[string]*syntheticCluster{}
	for i := 0; i < *clusters; i++ {
		c, e := db.CreateCluster(ctx, store.Cluster{OrganizationID: org.ID, FleetID: fleet.ID, SiteID: sites[i%4], Name: fmt.Sprintf("synthetic-%03d", i), Provider: "self-managed"}, "simulator", store.NewID())
		if e != nil {
			return e
		}
		token, e := db.IssueEnrollment(ctx, org.ID, c.ID, "simulator", store.NewID())
		if e != nil {
			return e
		}
		pub, priv, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return e
		}
		en := protocol.Enrollment{ClusterID: c.ID, ClusterUID: "synthetic-" + c.ID, Token: token.Token, PublicKey: protocol.EncodeKey(pub)}
		en.Proof = protocol.Proof(priv, protocol.EnrollmentMessage(en))
		if _, e = db.EnrollAgent(ctx, en, store.NewID()); e != nil {
			return e
		}
		report := protocol.Report{ClusterUID: en.ClusterUID, Version: 1, ObservedAt: time.Now(), KubernetesVersion: "v1.37.0"}
		for j := i; j < *nodes; j += *clusters {
			report.Nodes = append(report.Nodes, protocol.Node{Name: fmt.Sprintf("synthetic-%05d", j), UID: fmt.Sprintf("synthetic-node-%05d", j), Ready: true, Labels: map[string]string{"simulation": "true"}})
		}
		agent := &syntheticCluster{id: c.ID, key: protocol.KeyID(pub), report: report}
		inventory[c.ID] = agent
		if e = db.AcceptReport(ctx, c.ID, agent.key, store.NewID(), report); e != nil {
			return e
		}
		spec.Selection.ClusterIDs = append(spec.Selection.ClusterIDs, c.ID)
		spec.Policies = append(spec.Policies, campaign.PolicyBinding{ClusterID: c.ID, Policy: protocol.PolicyReference{Name: "synthetic-policy", UID: "synthetic-policy", Generation: 1}})
	}
	c, e := db.CreateCampaign(ctx, org.ID, store.NewID(), spec, "simulator", store.NewID())
	if e != nil {
		return e
	}
	c, e = db.StartCampaign(ctx, org.ID, c.ID, c.Revision, "simulator", store.NewID())
	if e != nil {
		return e
	}
	defer func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := db.Pool.Exec(shutdown, "UPDATE campaigns SET phase='Cancelled',reason='SimulationInterrupted' WHERE id=$1 AND phase NOT IN ('Succeeded','Failed','Cancelled','CompletedWithFailures')", c.ID)
		if err != nil {
			fmt.Fprintln(os.Stderr, "could not close synthetic campaign")
		}
	}()
	_, hub, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return e
	}
	ticks, issued := 0, 0
	lastRefresh := time.Now()
	for !campaign.Terminal(c.Phase) {
		if time.Since(lastRefresh) > 20*time.Second {
			for _, agent := range inventory {
				agent.report.Version++
				agent.report.ObservedAt = time.Now()
				if e = db.AcceptReport(ctx, agent.id, agent.key, store.NewID(), agent.report); e != nil {
					return e
				}
			}
			lastRefresh = time.Now()
		}
		result, e := db.ScheduleOnce(ctx, hub, "simulator", 0)
		if e != nil {
			return e
		}
		ticks++
		for _, id := range result.Operations {
			var cluster string
			if e = db.Pool.QueryRow(ctx, "SELECT cluster_id FROM node_operations WHERE id=$1", id).Scan(&cluster); e != nil {
				return e
			}
			agent := inventory[cluster]
			if agent == nil {
				return errors.New("simulation database contains other runnable campaigns; use a dedicated database")
			}
			if _, e = db.SyncNodeOperations(ctx, cluster, agent.key, store.NewID(), protocol.OperationSync{}, store.NewID()); e != nil {
				return e
			}
			status := protocol.OperationReport{OperationID: id, Sequence: 1, Phase: "Succeeded", Reason: "SyntheticSuccess", Events: []protocol.PhaseEvent{{Sequence: 1, Phase: "Succeeded", Reason: "SyntheticSuccess", Time: metav1.Now()}}}
			if _, e = db.SyncNodeOperations(ctx, cluster, agent.key, store.NewID(), protocol.OperationSync{Reports: []protocol.OperationReport{status}}, store.NewID()); e != nil {
				return e
			}
			issued++
		}
		c, e = db.GetCampaign(ctx, org.ID, c.ID)
		if e != nil {
			return e
		}
		if c.Phase == "Paused" {
			return fmt.Errorf("synthetic campaign paused: %s", c.Reason)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"synthetic": true, "organizationId": org.ID, "campaignId": c.ID, "nodes": *nodes, "clusters": *clusters, "issued": issued, "ticks": ticks, "elapsedSeconds": time.Since(began).Seconds(), "phase": c.Phase, "productionCapacityProven": false})
}
