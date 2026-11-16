package campaign

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"sort"

	"kordex.local/api/protocol"
)

type Target struct {
	ClusterID  string                   `json:"clusterId"`
	ClusterUID string                   `json:"clusterUid"`
	FleetID    string                   `json:"fleetId"`
	SiteID     string                   `json:"siteId"`
	Node       protocol.Node            `json:"node"`
	Policy     protocol.PolicyReference `json:"policy"`
	PlanDigest string                   `json:"planDigest,omitempty"`
	Ordinal    int                      `json:"ordinal"`
	Stage      int                      `json:"stage"`
}

// Plan interleaves sites and clusters so early stages do not concentrate on one failure domain.
func Plan(input []Target, spec Spec) ([]Target, string, error) {
	if len(input) == 0 || len(input) > MaxTargets {
		return nil, "", fmt.Errorf("target snapshot must contain one to %d nodes", MaxTargets)
	}
	if len(spec.Stages) != 4 {
		return nil, "", fmt.Errorf("four normalized stages required")
	}
	for i, stage := range spec.Stages {
		if stage.Name != stageNames[i] || (i < 3 && stage.Count < 1) {
			return nil, "", fmt.Errorf("invalid normalized stage")
		}
	}
	input = slices.Clone(input)
	sort.Slice(input, func(i, j int) bool {
		a, b := input[i], input[j]
		if a.SiteID != b.SiteID {
			return a.SiteID < b.SiteID
		}
		if a.ClusterID != b.ClusterID {
			return a.ClusterID < b.ClusterID
		}
		return a.Node.UID < b.Node.UID
	})
	groups := map[string][]Target{}
	keys := []string{}
	all := map[string]Target{}
	for _, target := range input {
		key := target.SiteID + "/" + target.ClusterID
		if _, ok := groups[key]; !ok {
			keys = append(keys, key)
		}
		groups[key] = append(groups[key], target)
		id := target.ClusterID + "/" + target.Node.UID
		if _, exists := all[id]; exists {
			return nil, "", fmt.Errorf("duplicate snapshot target")
		}
		all[id] = target
	}
	bySite := map[string][]string{}
	sites := []string{}
	for _, key := range keys {
		site := groups[key][0].SiteID
		if _, ok := bySite[site]; !ok {
			sites = append(sites, site)
		}
		bySite[site] = append(bySite[site], key)
	}
	keys = nil
	for round := 0; ; round++ {
		added := false
		for _, site := range sites {
			if round < len(bySite[site]) {
				keys = append(keys, bySite[site][round])
				added = true
			}
		}
		if !added {
			break
		}
	}
	ordered := make([]Target, 0, len(input))
	chosen := map[string]bool{}
	for _, ref := range spec.Selection.Canaries {
		id := ref.ClusterID + "/" + ref.NodeUID
		target, ok := all[id]
		if !ok || chosen[id] {
			return nil, "", fmt.Errorf("explicit canary is outside the target snapshot")
		}
		ordered = append(ordered, target)
		chosen[id] = true
	}
	for round := 0; len(ordered) < len(input); round++ {
		for _, key := range keys {
			if round >= len(groups[key]) {
				continue
			}
			target := groups[key][round]
			id := target.ClusterID + "/" + target.Node.UID
			if chosen[id] {
				continue
			}
			chosen[id] = true
			ordered = append(ordered, target)
		}
	}
	stage, remaining := 0, spec.Stages[0].Count
	for i := range ordered {
		for stage < 3 && remaining == 0 {
			stage++
			remaining = spec.Stages[stage].Count
		}
		ordered[i].Ordinal = i
		ordered[i].Stage = stage
		if stage < 3 {
			remaining--
		}
	}
	data, err := json.Marshal(ordered)
	if err != nil {
		return nil, "", err
	}
	digest := sha256.Sum256(data)
	return ordered, hex.EncodeToString(digest[:]), nil
}
