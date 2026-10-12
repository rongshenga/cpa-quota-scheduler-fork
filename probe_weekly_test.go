package main

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestWeeklyActivationGate(t *testing.T) {
	for _, tc := range []struct {
		name         string
		kind         WindowKind
		lazy         []ProbeWindowKind
		window, want bool
	}{
		{"weekly", WindowWeekly, []ProbeWindowKind{ProbeWindowLong}, true, true},
		{"mixed", WindowWeekly, []ProbeWindowKind{ProbeWindowFiveHour, ProbeWindowLong}, true, true},
		{"weekly not lazy", WindowWeekly, []ProbeWindowKind{ProbeWindowFiveHour}, true, false},
		{"monthly", WindowMonthly, []ProbeWindowKind{ProbeWindowLong}, true, false},
		{"explicit send window", WindowWeekly, []ProbeWindowKind{ProbeWindowLong}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := (probeSendGate{WindowAllowed: tc.window}).withWeeklyActivation(tc.lazy, ParsedQuota{LongWindow: &QuotaWindow{Kind: tc.kind}})
			if g.Allowed != tc.want {
				t.Fatalf("gate=%+v", g)
			}
		})
	}
}

func TestConfirmedWeeklyWakeOnceAtReset(t *testing.T) {
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	reset := now.Add(7 * 24 * time.Hour)
	base := ResetProbeBaseline(reset, 50, 7*24*time.Hour)
	base.WindowKind = WindowWeekly
	c := NewProbeController(now)
	c.SetWindow(1, ProbeWindowLong, ProbeWindow{State: ProbeConfirmed, Baseline: base, Deadline: confirmedWeeklyDeadline(ProbeWindowLong, base)})
	want := reset.Add(time.Minute)
	if !c.NextDeadline().Equal(want) {
		t.Fatal(c.NextDeadline())
	}
	for _, at := range []time.Time{now.Add(30 * time.Minute), reset, want.Add(-time.Nanosecond)} {
		if intents := c.Advance(1, ProbeEvent{Kind: ProbeEventDeadline, Window: ProbeWindowLong, Now: at, RefreshMode: RefreshModeDormant}); len(intents) != 0 {
			t.Fatalf("early poll: %v", intents)
		}
	}
	intents := c.Advance(1, ProbeEvent{Kind: ProbeEventDeadline, Window: ProbeWindowLong, Now: want, RefreshMode: RefreshModeDormant})
	if len(intents) != 1 || intents[0].Class != OperationProbePrecheck {
		t.Fatalf("want one read: %v", intents)
	}
	if again := c.Advance(1, ProbeEvent{Kind: ProbeEventDeadline, Window: ProbeWindowLong, Now: want}); len(again) != 0 {
		t.Fatal("duplicate wake")
	}
	if !c.NextDeadline().IsZero() {
		t.Fatal("pending check retained timer")
	}
	for _, kind := range []WindowKind{WindowMonthly, WindowFiveHour} {
		other := base
		other.WindowKind = kind
		if !confirmedWeeklyDeadline(ProbeWindowLong, other).IsZero() {
			t.Fatal("changed non-weekly timer")
		}
	}
}

func TestConfirmedWeeklyBootstrapRestoresPersistentDeadline(t *testing.T) {
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	r := newDueProbeRuntime(t, now, newProbeFixtureHost())
	b, _ := r.bindings.Lookup("a")
	base := ResetProbeBaseline(now.Add(7*24*time.Hour), 50, 7*24*time.Hour)
	base.WindowKind = WindowWeekly
	r.probeController.SetWindow(b.Instance, ProbeWindowLong, ProbeWindow{State: ProbeConfirmed, Baseline: base})
	if err := r.persistProbeWindows(); err != nil {
		t.Fatal(err)
	}
	if err := r.bootstrapProbeWindows(); err != nil {
		t.Fatal(err)
	}
	want := base.ResetAt.Add(time.Minute)
	s, err := r.runtimeStore.PersistentSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if !s.ProbeWindows[b.Instance][ProbeWindowLong].Deadline.Equal(want) {
		t.Fatal("missing persistent expiry")
	}
	// Loading the persisted controller preserves the exact deadline after restart.
	c := NewProbeController(now.Add(time.Hour))
	c.Load(s.ProbeWindows)
	w, _ := c.Window(b.Instance, ProbeWindowLong)
	if w.State != ProbeConfirmed || !w.Deadline.Equal(want) {
		t.Fatal(w)
	}
	if err := r.bootstrapProbeWindows(); err != nil {
		t.Fatal(err)
	}
	w, _ = r.probeController.Window(b.Instance, ProbeWindowLong)
	if !w.Deadline.Equal(want) {
		t.Fatal("bootstrap shifted known expiry")
	}
}

func TestWeeklyScheduledDeferralMigration(t *testing.T) {
	now := time.Date(2026, 9, 7, 11, 10, 1, 0, time.UTC)
	cfg := DefaultConfig()
	cfg.ProbeSendTimezone = "UTC"
	cfg.ProbeTriggerMinutes = []int{720}
	for _, tc := range []struct {
		name              string
		kind              WindowKind
		attempt, ordinary bool
		want              bool
	}{
		{"weekly deferred", WindowWeekly, false, false, true},
		{"monthly deferred", WindowMonthly, false, false, false},
		{"WAL attempt", WindowWeekly, true, false, false},
		{"ordinary retry", WindowWeekly, false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			deadline := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
			if tc.ordinary {
				deadline = now.Add(15 * time.Minute)
			}
			s := PersistentState{ProbeWindows: map[AuthInstanceID]map[ProbeWindowKind]ProbeWindow{1: {ProbeWindowLong: {State: ProbeRetryWait, Baseline: ProbeBaseline{WindowKind: tc.kind, SuspectedLazy: true}, Deadline: deadline}}}, ProbeAttempts: map[AuthInstanceID]ProbeAttempt{}}
			if tc.attempt {
				s.ProbeAttempts[1] = ProbeAttempt{AttemptID: "in-flight", SuppressUntil: now.Add(time.Hour)}
			}
			if got := rearmScheduledWeeklyWindows(&s, cfg, now); got != tc.want {
				t.Fatalf("changed=%v want=%v", got, tc.want)
			}
			if tc.want && !s.ProbeWindows[1][ProbeWindowLong].Deadline.Equal(now) {
				t.Fatal("not rearmed")
			}
			if rearmScheduledWeeklyWindows(&s, cfg, now) {
				t.Fatal("migration repeated")
			}
		})
	}
	if got := probeWindowFailureDeadline(ProbeWindowLong, ProbeBaseline{WindowKind: WindowWeekly}, cfg, now, 1); !got.Equal(now.Add(15 * time.Minute)) {
		t.Fatal(got)
	}
	if got := probeWindowFailureDeadline(ProbeWindowFiveHour, ProbeBaseline{WindowKind: WindowFiveHour}, cfg, now, 1); got.Hour() != 12 {
		t.Fatal(got)
	}
}

func TestWeeklyDeferralMigratesAfterConfigurationLoads(t *testing.T) {
	now := time.Date(2026, 9, 7, 11, 0, 1, 0, time.UTC)
	r := newDueProbeRuntime(t, now, newProbeFixtureHost())
	b, _ := r.bindings.Lookup("a")
	base := ResetProbeBaseline(now.Add(7*24*time.Hour), 0, 7*24*time.Hour)
	base.WindowKind = WindowWeekly
	base.SuspectedLazy = true
	r.probeController.SetWindow(b.Instance, ProbeWindowLong, ProbeWindow{State: ProbeRetryWait, Baseline: base, Deadline: time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)})
	if err := r.persistProbeWindows(); err != nil {
		t.Fatal(err)
	}
	cfg := r.state.Config()
	cfg.ProbeSendTimezone = "UTC"
	cfg.ProbeTriggerMinutes = []int{720}
	r.state.ReplaceConfig(cfg)
	if err := r.bootstrapProbeWindows(); err != nil {
		t.Fatal(err)
	}
	w, _ := r.probeController.Window(b.Instance, ProbeWindowLong)
	if w.Deadline.After(now) {
		t.Fatalf("weekly still parked: %+v", w)
	}
	s, err := r.runtimeStore.PersistentSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if s.ProbeWindows[b.Instance][ProbeWindowLong].Deadline.After(now) {
		t.Fatal("migration not persisted")
	}
}

func TestWeeklyAutomaticActivationOutsideSchedule(t *testing.T) {
	now := time.Date(2026, 9, 7, 11, 0, 0, 0, time.UTC)
	for _, mixed := range []bool{false, true} {
		t.Run(fmt.Sprintf("mixed=%v", mixed), func(t *testing.T) {
			host := newProbeFixtureHost()
			body := func(used int) []byte {
				five := ""
				if mixed {
					five = fmt.Sprintf(`"primary_window":{"used_percent":%d,"limit_window_seconds":18000,"reset_at":%q},`, used, now.Add(5*time.Hour).Format(time.RFC3339))
				}
				return []byte(fmt.Sprintf(`{"rate_limit":{%s"secondary_window":{"used_percent":%d,"limit_window_seconds":604800,"reset_at":%q}}}`, five, used, now.Add(7*24*time.Hour).Format(time.RFC3339)))
			}
			host.quota = [][]byte{body(0), body(1)}
			r := newDueProbeRuntime(t, now, host)
			b, _ := r.bindings.Lookup("a")
			cfg := r.state.Config()
			cfg.ProbeSendTimezone = "UTC"
			cfg.ProbeTriggerMinutes = []int{420, 720, 1020}
			r.state.ReplaceConfig(cfg)
			r.probeController.RemoveWindow(b.Instance, ProbeWindowFiveHour)
			base := ResetProbeBaseline(now.Add(7*24*time.Hour), 0, 7*24*time.Hour)
			base.WindowKind = WindowWeekly
			base.SuspectedLazy = true
			r.probeController.SetWindow(b.Instance, ProbeWindowLong, ProbeWindow{State: ProbePendingCheck, Baseline: base})
			if mixed {
				five := ResetProbeBaseline(now.Add(5*time.Hour), 0, 5*time.Hour)
				five.WindowKind = WindowFiveHour
				five.SuspectedLazy = true
				r.probeController.SetWindow(b.Instance, ProbeWindowFiveHour, ProbeWindow{State: ProbePendingCheck, Baseline: five})
			}
			if err := r.persistProbeWindows(); err != nil {
				t.Fatal(err)
			}
			if err := r.RunProbeDueOnce(context.Background()); err != nil {
				t.Fatal(err)
			}
			if posts, urls := probePOSTCount(host); posts != 1 {
				t.Fatalf("posts=%d urls=%v", posts, urls)
			}
			w, _ := r.probeController.Window(b.Instance, ProbeWindowLong)
			if w.State != ProbeConfirmed {
				t.Fatalf("weekly=%+v", w)
			}
			fields := probeEventFields(t, r, now, "probe.activation_sent")
			if fields["weekly_bypassed_trigger_gate"] != true {
				t.Fatal(fields)
			}
		})
	}
}
