package main

import (
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func codexPickRequest() pluginapi.SchedulerPickRequest {
	return pluginapi.SchedulerPickRequest{Provider: "codex", Model: "gpt-5-codex"}
}

// A selected account and a delegation are the plugin working correctly. Neither
// belongs in a 200-entry ring shared with reset-probe history.
func TestRoutineSchedulingIsNotRecorded(t *testing.T) {
	now := time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)
	for name, decision := range map[string]PickDecision{
		"selected": {AuthID: "auth-1", Handled: true, Reason: "selected"},
		"fallback": {Handled: true, DelegateBuiltin: pluginapi.SchedulerBuiltinFillFirst, Reason: "fallback_fill_first"},
	} {
		store := NewPluginState(DefaultConfig())
		logSchedulerDecision(store, codexPickRequest(), decision, now)
		if got := len(store.Snapshot(now).Logs); got != 0 {
			t.Errorf("%s: logs = %d, want 0", name, got)
		}
	}
}

// Requests for other providers reach scheduler.pick too. They are not this
// plugin's business and must not consume ring capacity.
func TestNonCodexAndDisabledDecisionsAreNotRecorded(t *testing.T) {
	now := time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)
	for _, reason := range []string{"provider_not_codex", "handle_disabled"} {
		store := NewPluginState(DefaultConfig())
		logSchedulerDecision(store, pluginapi.SchedulerPickRequest{Provider: "claude"}, PickDecision{Reason: reason}, now)
		if got := len(store.Snapshot(now).Logs); got != 0 {
			t.Errorf("reason %q: logs = %d, want 0", reason, got)
		}
	}
}

// A Codex shortage is a real fault and must still surface.
func TestCodexShortageIsRecorded(t *testing.T) {
	now := time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)
	for _, reason := range []string{"no_codex_candidates", "no_selectable_account"} {
		store := NewPluginState(DefaultConfig())
		logSchedulerDecision(store, codexPickRequest(), PickDecision{Reason: reason}, now)
		logs := store.Snapshot(now).Logs
		if len(logs) != 1 {
			t.Fatalf("reason %q: logs = %d, want 1", reason, len(logs))
		}
		if logs[0].Fields["reason"] != reason {
			t.Errorf("reason %q: fields = %#v", reason, logs[0].Fields)
		}
	}
}

// The shortage repeats on every request while it lasts. One condition is one
// entry, otherwise the fault floods the ring it was kept for.
func TestRepeatedShortageIsRecordedOnce(t *testing.T) {
	now := time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)
	store := NewPluginState(DefaultConfig())
	for i := 0; i < 50; i++ {
		logSchedulerDecision(store, codexPickRequest(), PickDecision{Reason: "no_selectable_account"}, now)
	}
	if got := len(store.Snapshot(now).Logs); got != 1 {
		t.Fatalf("logs = %d, want 1 after 50 identical faults", got)
	}
}

// A different fault is a different condition and is not suppressed.
func TestDifferentShortageIsRecordedAgain(t *testing.T) {
	now := time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)
	store := NewPluginState(DefaultConfig())
	logSchedulerDecision(store, codexPickRequest(), PickDecision{Reason: "no_selectable_account"}, now)
	logSchedulerDecision(store, codexPickRequest(), PickDecision{Reason: "no_codex_candidates"}, now)
	if got := len(store.Snapshot(now).Logs); got != 2 {
		t.Fatalf("logs = %d, want 2 for two distinct faults", got)
	}
}

// Recovery must re-arm the fault: a shortage that returns after accounts came
// back is news again, not a duplicate of the earlier one.
func TestShortageRecordsAgainAfterRecovery(t *testing.T) {
	now := time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)
	store := NewPluginState(DefaultConfig())
	logSchedulerDecision(store, codexPickRequest(), PickDecision{Reason: "no_selectable_account"}, now)
	logSchedulerDecision(store, codexPickRequest(), PickDecision{AuthID: "auth-1", Handled: true, Reason: "selected"}, now)
	logSchedulerDecision(store, codexPickRequest(), PickDecision{Reason: "no_selectable_account"}, now)
	if got := len(store.Snapshot(now).Logs); got != 2 {
		t.Fatalf("logs = %d, want 2 (fault, recovery, fault again)", got)
	}
}

// The escape hatch restores the old behaviour, including for the routine
// decisions the filter drops, and does not dedup.
func TestVerboseFlagRestoresEveryDecision(t *testing.T) {
	now := time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)
	store := NewPluginState(verboseSchedulerLogConfig())
	for i := 0; i < 5; i++ {
		logSchedulerDecision(store, codexPickRequest(), PickDecision{AuthID: "auth-1", Handled: true, Reason: "selected"}, now)
	}
	if got := len(store.Snapshot(now).Logs); got != 5 {
		t.Fatalf("logs = %d, want 5 with log_scheduler_decisions on", got)
	}
}

// The probe history the ring exists to preserve must survive request traffic
// that would previously have evicted it.
func TestProbeHistorySurvivesRequestTraffic(t *testing.T) {
	now := time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)
	store := NewPluginState(DefaultConfig())
	store.RecordLog("info", "probe.verified", "额度周期激活验证完成", map[string]any{"auth_id": "auth-1"}, now)
	for i := 0; i < DefaultConfig().MaxLogEntries*2; i++ {
		logSchedulerDecision(store, codexPickRequest(), PickDecision{AuthID: "auth-1", Handled: true, Reason: "selected"}, now)
	}
	for _, entry := range store.Snapshot(now).Logs {
		if entry.Event == "probe.verified" {
			return
		}
	}
	t.Fatal("probe.verified was evicted by routine scheduling traffic")
}
