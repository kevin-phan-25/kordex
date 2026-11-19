package campaign

import "testing"

func TestConcurrencyLimitsBoundsAndSerializedSlots(t *testing.T) {
	for _, limits := range []Limits{
		DefaultLimits(),
		{Organization: 1000, Fleet: 1000, Site: 1000, Zone: 1000, Cluster: 1, Node: 1, MaxUnavailablePerSite: 1000},
		{Organization: 8, Fleet: 4, Site: 2, Zone: 2, Cluster: 1, Node: 1, MaxUnavailablePerSite: 3},
	} {
		if err := limits.Validate(); err != nil {
			t.Errorf("valid limits rejected: %+v: %v", limits, err)
		}
	}
	for _, limits := range []Limits{
		{Organization: 0, Fleet: 1, Site: 1, Zone: 1, Cluster: 1, Node: 1, MaxUnavailablePerSite: 1},
		{Organization: 1001, Fleet: 1, Site: 1, Zone: 1, Cluster: 1, Node: 1, MaxUnavailablePerSite: 1},
		{Organization: 1, Fleet: 1, Site: 1, Zone: 0, Cluster: 1, Node: 1, MaxUnavailablePerSite: 1},
		{Organization: 1, Fleet: 1, Site: 1, Zone: 1, Cluster: 2, Node: 1, MaxUnavailablePerSite: 1},
		{Organization: 1, Fleet: 1, Site: 1, Zone: 1, Cluster: 1, Node: 2, MaxUnavailablePerSite: 1},
		{Organization: 1, Fleet: 1, Site: 1, Zone: 1, Cluster: 1, Node: 1, MaxUnavailablePerSite: 0},
	} {
		if err := limits.Validate(); err == nil {
			t.Errorf("invalid limits accepted: %+v", limits)
		}
	}
}

func TestLegacyConcurrencyLimitsDefaultToOneZoneSlot(t *testing.T) {
	legacy := Limits{Organization: 4, Fleet: 3, Site: 2, Cluster: 1, Node: 1, MaxUnavailablePerSite: 2}
	if legacy.Validate() == nil {
		t.Fatal("a missing zone limit was accepted before normalization")
	}
	normalized := legacy.WithDefaults()
	if normalized.Zone != 1 || normalized.Validate() != nil {
		t.Fatalf("legacy limit did not receive conservative zone default: %+v", normalized)
	}
}
