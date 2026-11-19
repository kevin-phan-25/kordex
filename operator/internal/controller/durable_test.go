package controller

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"kordex.local/api/protocol"
)

func TestLatestPhaseTimeUsesMostRecentDurablePhase(t *testing.T) {
	first := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	second := first.Add(2 * time.Minute)
	events := []protocol.PhaseEvent{
		{Phase: "Draining", Time: metav1.NewTime(first)},
		{Phase: "Blocked", Time: metav1.NewTime(first.Add(time.Minute))},
		{Phase: "Draining", Time: metav1.NewTime(second)},
	}
	got, ok := latestPhaseTime(events, "Draining")
	if !ok || !got.Equal(second) {
		t.Fatalf("latest Draining event = %v, found=%t; want %v", got, ok, second)
	}
	if _, ok = latestPhaseTime(events, "Rebooting"); ok {
		t.Fatal("missing Rebooting phase reported as present")
	}
}
