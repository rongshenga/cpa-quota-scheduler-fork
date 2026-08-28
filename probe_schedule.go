package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	// Embed the zone database so probe_send_timezone resolves identically no
	// matter what the host image ships. Without it a missing /usr/share/zoneinfo
	// degrades silently to time.Local, which would shift every send window.
	_ "time/tzdata"
)

// probeSendWindow is a local-clock range during which reset-probe activation
// requests may be sent. Start/End are minutes since local midnight. A window
// whose End is not after its Start wraps past midnight (e.g. 22:00-02:00).
type probeSendWindow struct {
	Start int
	End   int
}

const minutesPerDay = 24 * 60

const probeTriggerGrace = 10 * time.Minute

// probeFailureDeadline returns the next retry deadline for a probe operation.
// When explicit trigger times are configured, retrying inside the same grace
// window could send multiple activation requests for one scheduled slot. Push
// unsent failures to the next trigger so each account gets at most one
// activation attempt per slot. With no trigger schedule, preserve the
// upstream exponential-ish backoff behaviour.
func probeFailureDeadline(triggerMinutes []int, timezone string, now time.Time, retryCount int) time.Time {
	if len(triggerMinutes) > 0 {
		if next := nextProbeTriggerAt(triggerMinutes, probeSendLocation(timezone), now); !next.IsZero() {
			return next
		}
	}
	return now.Add(probeBackoff(retryCount))
}

// Contains reports whether the given minute-of-day falls inside the window.
// The start bound is inclusive and the end bound exclusive, so adjacent
// windows never double-count a single minute.
func (w probeSendWindow) Contains(minuteOfDay int) bool {
	if w.End > w.Start {
		return minuteOfDay >= w.Start && minuteOfDay < w.End
	}
	// Wraps past midnight.
	return minuteOfDay >= w.Start || minuteOfDay < w.End
}

func (w probeSendWindow) String() string {
	return fmt.Sprintf("%02d:%02d-%02d:%02d", w.Start/60, w.Start%60, w.End/60, w.End%60)
}

func parseClockMinute(text string) (int, error) {
	parts := strings.Split(strings.TrimSpace(text), ":")
	if len(parts) != 2 {
		return 0, fmt.Errorf("expected HH:MM, got %q", text)
	}
	hour, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil || hour < 0 || hour > 23 {
		return 0, fmt.Errorf("invalid hour in %q", text)
	}
	minute, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil || minute < 0 || minute > 59 {
		return 0, fmt.Errorf("invalid minute in %q", text)
	}
	return hour*60 + minute, nil
}

// parseProbeSendWindow accepts "HH:MM-HH:MM".
func parseProbeSendWindow(text string) (probeSendWindow, error) {
	raw := strings.TrimSpace(text)
	if raw == "" {
		return probeSendWindow{}, fmt.Errorf("empty window")
	}
	parts := strings.Split(raw, "-")
	if len(parts) != 2 {
		return probeSendWindow{}, fmt.Errorf("expected HH:MM-HH:MM, got %q", text)
	}
	start, err := parseClockMinute(parts[0])
	if err != nil {
		return probeSendWindow{}, err
	}
	end, err := parseClockMinute(parts[1])
	if err != nil {
		return probeSendWindow{}, err
	}
	if start == end {
		return probeSendWindow{}, fmt.Errorf("window %q is empty (start equals end)", text)
	}
	return probeSendWindow{Start: start, End: end}, nil
}

func parseProbeSendWindows(items []string) ([]probeSendWindow, error) {
	windows := make([]probeSendWindow, 0, len(items))
	for _, item := range items {
		if strings.TrimSpace(item) == "" {
			continue
		}
		window, err := parseProbeSendWindow(item)
		if err != nil {
			return nil, err
		}
		windows = append(windows, window)
	}
	return windows, nil
}

// parseProbeTriggerTimes accepts a list of HH:MM wall-clock times. Empty
// items are ignored so values assembled from a comma-separated management
// setting remain forgiving, while malformed non-empty items are rejected.
func parseProbeTriggerTimes(items []string) ([]int, error) {
	minutes := make([]int, 0, len(items))
	seen := make(map[int]struct{}, len(items))
	for _, item := range items {
		if strings.TrimSpace(item) == "" {
			continue
		}
		minute, err := parseClockMinute(item)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[minute]; ok {
			continue
		}
		seen[minute] = struct{}{}
		minutes = append(minutes, minute)
	}
	sort.Ints(minutes)
	return minutes, nil
}

func normalizeProbeTriggerMinutes(values []int) []int {
	if len(values) == 0 {
		return nil
	}
	minutes := make([]int, 0, len(values))
	seen := make(map[int]struct{}, len(values))
	for _, minute := range values {
		if minute < 0 || minute >= minutesPerDay {
			continue
		}
		if _, ok := seen[minute]; ok {
			continue
		}
		seen[minute] = struct{}{}
		minutes = append(minutes, minute)
	}
	sort.Ints(minutes)
	return minutes
}

func formatProbeTriggerTimes(minutes []int) string {
	if len(minutes) == 0 {
		return ""
	}
	parts := make([]string, 0, len(minutes))
	for _, minute := range minutes {
		if minute < 0 || minute >= minutesPerDay {
			continue
		}
		parts = append(parts, fmt.Sprintf("%02d:%02d", minute/60, minute%60))
	}
	return strings.Join(parts, ",")
}

// nextProbeTriggerAt returns the next configured wall-clock trigger strictly
// after now. The strict comparison prevents the refresh loop from repeatedly
// firing the same trigger when it wakes exactly at the scheduled instant.
func nextProbeTriggerAt(minutes []int, loc *time.Location, now time.Time) time.Time {
	minutes = normalizeProbeTriggerMinutes(minutes)
	if len(minutes) == 0 {
		return time.Time{}
	}
	if loc == nil {
		loc = time.Local
	}
	local := now.In(loc)
	day := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, loc)
	for _, minute := range minutes {
		if minute < 0 || minute >= minutesPerDay {
			continue
		}
		candidate := day.Add(time.Duration(minute) * time.Minute)
		if candidate.After(now) {
			return candidate
		}
	}
	if len(minutes) == 0 {
		return time.Time{}
	}
	first := minutes[0]
	return day.Add(24*time.Hour + time.Duration(first)*time.Minute)
}

func probeTriggerAllowedAt(minutes []int, loc *time.Location, now time.Time) bool {
	if len(minutes) == 0 {
		return true
	}
	if loc == nil {
		loc = time.Local
	}
	local := now.In(loc)
	day := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, loc)
	for _, minute := range minutes {
		if minute < 0 || minute >= minutesPerDay {
			continue
		}
		start := day.Add(time.Duration(minute) * time.Minute)
		if !now.Before(start) && now.Before(start.Add(probeTriggerGrace)) {
			return true
		}
	}
	return false
}

// probeSendLocation resolves the configured timezone, falling back to the
// process-local zone so a bad name degrades to current behaviour instead of
// silently shifting every window.
func probeSendLocation(name string) *time.Location {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return time.Local
	}
	loc, err := time.LoadLocation(trimmed)
	if err != nil {
		return time.Local
	}
	return loc
}

// probeSendAllowedAt reports whether an activation request may be sent now.
// An empty window list means "always allowed", preserving upstream behaviour
// for anyone who does not configure a schedule.
func probeSendAllowedAt(windows []probeSendWindow, loc *time.Location, now time.Time) bool {
	if len(windows) == 0 {
		return true
	}
	if loc == nil {
		loc = time.Local
	}
	local := now.In(loc)
	minuteOfDay := local.Hour()*60 + local.Minute()
	for _, window := range windows {
		if window.Contains(minuteOfDay) {
			return true
		}
	}
	return false
}

func formatProbeSendWindows(windows []probeSendWindow) string {
	if len(windows) == 0 {
		return ""
	}
	parts := make([]string, 0, len(windows))
	for _, window := range windows {
		parts = append(parts, window.String())
	}
	return strings.Join(parts, ",")
}
