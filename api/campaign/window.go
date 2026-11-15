package campaign

import (
	"fmt"
	"time"
	_ "time/tzdata"
)

// Windows use explicit RFC3339 offsets. Matching IANA offsets reject nonexistent local times
// and require callers to disambiguate repeated DST times rather than silently choosing one.
func (w Window) Validate() error {
	location, err := time.LoadLocation(w.TimeZone)
	if err != nil || w.TimeZone == "" {
		return fmt.Errorf("invalid IANA time zone")
	}
	if w.Start.IsZero() || !w.End.After(w.Start) || w.End.Sub(w.Start) > 24*time.Hour || w.End.Sub(w.Start) < time.Minute {
		return fmt.Errorf("window must last one minute to 24 hours")
	}
	for _, instant := range []time.Time{w.Start, w.End} {
		_, supplied := instant.Zone()
		_, actual := instant.In(location).Zone()
		if supplied != actual {
			return fmt.Errorf("window offset does not match its IANA time zone")
		}
	}
	return nil
}
func (s Spec) CurrentWindow(now time.Time) (Window, bool) {
	for _, w := range s.Windows {
		if !now.Before(w.Start) && now.Before(w.End) {
			return w, true
		}
	}
	return Window{}, false
}
func (s Spec) HasFutureWindow(now time.Time) bool {
	for _, w := range s.Windows {
		if w.End.After(now) {
			return true
		}
	}
	return false
}
