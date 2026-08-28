package main

import (
	"testing"
	"time"
)

func mustWindows(t *testing.T, items ...string) []probeSendWindow {
	t.Helper()
	w, err := parseProbeSendWindows(items)
	if err != nil {
		t.Fatalf("parseProbeSendWindows(%v): %v", items, err)
	}
	return w
}

func TestProbeSendAllowedAtEmptyMeansAlways(t *testing.T) {
	if !probeSendAllowedAt(nil, time.UTC, time.Date(2026, 8, 28, 3, 0, 0, 0, time.UTC)) {
		t.Fatal("empty window list must preserve upstream always-allowed behaviour")
	}
}

func TestProbeSendAllowedAtUserSchedule(t *testing.T) {
	loc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Skipf("tzdata unavailable: %v", err)
	}
	windows := mustWindows(t, "07:00-07:30", "12:00-12:30", "17:00-17:30")
	cases := []struct {
		hour, min int
		want      bool
	}{
		{7, 0, true}, // window start is inclusive
		{7, 29, true},
		{7, 30, false}, // window end is exclusive
		{12, 15, true},
		{17, 29, true},
		{3, 0, false}, // overnight: the case this whole feature exists for
		{22, 0, false},
		{10, 0, false}, // working, but not an activation slot
	}
	for _, c := range cases {
		now := time.Date(2026, 8, 28, c.hour, c.min, 0, 0, loc)
		if got := probeSendAllowedAt(windows, loc, now); got != c.want {
			t.Errorf("%02d:%02d = %v, want %v", c.hour, c.min, got, c.want)
		}
	}
}

func TestProbeSendWindowWrapsMidnight(t *testing.T) {
	windows := mustWindows(t, "22:00-02:00")
	for _, c := range []struct {
		hour int
		want bool
	}{{22, true}, {23, true}, {0, true}, {1, true}, {2, false}, {12, false}} {
		now := time.Date(2026, 8, 28, c.hour, 0, 0, 0, time.UTC)
		if got := probeSendAllowedAt(windows, time.UTC, now); got != c.want {
			t.Errorf("hour %02d = %v, want %v", c.hour, got, c.want)
		}
	}
}

func TestProbeSendAllowedUsesConfiguredZoneNotUTC(t *testing.T) {
	loc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Skipf("tzdata unavailable: %v", err)
	}
	// 23:30 UTC is 07:30+1d in Shanghai. Guards against the gate silently
	// running on UTC and firing ~8h off from the operator's intent.
	utcInstant := time.Date(2026, 8, 27, 23, 10, 0, 0, time.UTC)
	if !probeSendAllowedAt(mustWindows(t, "07:00-07:30"), loc, utcInstant) {
		t.Fatal("07:10 Asia/Shanghai must be allowed regardless of UTC wall clock")
	}
	if probeSendAllowedAt(mustWindows(t, "07:00-07:30"), time.UTC, utcInstant) {
		t.Fatal("same instant must be rejected when the zone really is UTC")
	}
}

func TestParseProbeSendWindowRejectsBadInput(t *testing.T) {
	for _, bad := range []string{"", "7:00", "07:00", "07:00-07:00", "25:00-26:00", "07:60-08:00", "07:00-08:00-09:00"} {
		if _, err := parseProbeSendWindow(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

func TestBadTimezoneFallsBackToLocal(t *testing.T) {
	if probeSendLocation("Not/AZone") != time.Local {
		t.Fatal("unknown zone must degrade to time.Local, not nil")
	}
}

func TestProbeTriggerTimesAreSortedAndDeduplicated(t *testing.T) {
	got, err := parseProbeTriggerTimes([]string{"17:00", "07:00", "17:00", "12:00"})
	if err != nil {
		t.Fatal(err)
	}
	want := []int{7 * 60, 12 * 60, 17 * 60}
	if len(got) != len(want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %#v, want %#v", got, want)
		}
	}
}

func TestNormalizeProbeTriggerMinutesDropsInvalidValues(t *testing.T) {
	got := normalizeProbeTriggerMinutes([]int{17 * 60, -1, 7 * 60, 24 * 60, 7 * 60})
	want := []int{7 * 60, 17 * 60}
	if len(got) != len(want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %#v, want %#v", got, want)
		}
	}
}

func TestNextProbeTriggerAtUsesConfiguredZone(t *testing.T) {
	loc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Skipf("tzdata unavailable: %v", err)
	}
	triggers := []int{7 * 60, 12 * 60, 17 * 60}
	before := time.Date(2026, 8, 28, 6, 59, 0, 0, loc)
	if got, want := nextProbeTriggerAt(triggers, loc, before), time.Date(2026, 8, 28, 7, 0, 0, 0, loc); !got.Equal(want) {
		t.Fatalf("next before first = %s, want %s", got, want)
	}
	after := time.Date(2026, 8, 28, 17, 1, 0, 0, loc)
	wantNext := time.Date(2026, 8, 29, 7, 0, 0, 0, loc)
	if got := nextProbeTriggerAt(triggers, loc, after); !got.Equal(wantNext) {
		t.Fatalf("next after last = %s, want %s", got, wantNext)
	}
}

func TestProbeTriggerAllowedGrace(t *testing.T) {
	loc := time.FixedZone("CST", 8*60*60)
	triggers := []int{7 * 60}
	if !probeTriggerAllowedAt(triggers, loc, time.Date(2026, 8, 28, 7, 0, 0, 0, loc)) {
		t.Fatal("trigger start must be allowed")
	}
	if !probeTriggerAllowedAt(triggers, loc, time.Date(2026, 8, 28, 7, 9, 59, 0, loc)) {
		t.Fatal("trigger grace must be allowed")
	}
	if probeTriggerAllowedAt(triggers, loc, time.Date(2026, 8, 28, 7, 10, 0, 0, loc)) {
		t.Fatal("trigger after grace must be rejected")
	}
}

func TestProbeFailureDeadlineSkipsRemainderOfTriggerGrace(t *testing.T) {
	loc := time.FixedZone("CST", 8*60*60)
	now := time.Date(2026, 8, 28, 7, 1, 0, 0, loc)
	got := probeFailureDeadline([]int{7 * 60, 12 * 60, 17 * 60}, "Asia/Shanghai", now, 1)
	want := time.Date(2026, 8, 28, 12, 0, 0, 0, loc)
	if !got.Equal(want) {
		t.Fatalf("failure at %s retried at %s, want %s", now, got, want)
	}
}

func TestProbeFailureDeadlineKeepsDefaultBackoffWithoutTriggers(t *testing.T) {
	now := time.Date(2026, 8, 28, 7, 1, 0, 0, time.UTC)
	if got, want := probeFailureDeadline(nil, "", now, 2), now.Add(5*time.Minute); !got.Equal(want) {
		t.Fatalf("default retry deadline = %s, want %s", got, want)
	}
}
