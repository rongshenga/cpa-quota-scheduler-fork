package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"testing"
	"time"
)

func blockedProbeFixture(t *testing.T, now time.Time, host *sequenceProbeHost, sent bool) (*QuotaRefresher, RuntimeBinding) {
	t.Helper()
	r := newDueProbeRuntime(t, now, host)
	t.Cleanup(r.Stop)
	cfg := r.state.Config()
	cfg.ProbeSendTimezone = "Asia/Shanghai"
	cfg.ProbeTriggerMinutes = []int{7 * 60, 12 * 60, 17 * 60}
	r.state.ReplaceConfig(cfg)
	binding, _ := r.bindings.Lookup("a")
	base := ResetProbeBaseline(now.Add(-4*24*time.Hour), 0, 5*time.Hour)
	base.WindowKind = WindowFiveHour
	base.SuspectedLazy = true
	window := ProbeWindow{State: ProbeAuthBlocked, Baseline: base, AuthBlockedAtLogin: binding.Login}
	if sent {
		window.AttemptID = "old-sent"
		seq, err := r.probeFence.Next()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.runtimeStore.Update(func(s *PersistentState) error {
			s.ProbeAttempts[binding.Instance] = ProbeAttempt{Instance: binding.Instance, AttemptID: window.AttemptID, Phase: ProbeAttemptSentUnknown, Windows: []ProbeWindowKind{ProbeWindowFiveHour}, CreatedAt: now.Add(-4 * 24 * time.Hour), SendFenceSeq: seq, VerifyNotBefore: now.Add(-time.Hour)}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	r.probeController.SetWindow(binding.Instance, ProbeWindowFiveHour, window)
	if err := r.persistProbeWindows(); err != nil {
		t.Fatal(err)
	}
	if err := r.bindings.MarkAuthBlocked("a"); err != nil {
		t.Fatal(err)
	}
	return r, binding
}

func waitForAuthRecovery(t *testing.T, r *QuotaRefresher, binding RuntimeBinding, done func(ProbeWindow) bool) ProbeWindow {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		state, err := r.runtimeStore.PersistentSnapshot()
		if err != nil {
			t.Fatal(err)
		}
		window := state.ProbeWindows[binding.Instance][ProbeWindowFiveHour]
		_, attemptExists := state.ProbeAttempts[binding.Instance]
		if !state.Bindings["a"].AuthBlocked && !attemptExists && done(window) {
			return window
		}
		if time.Now().After(deadline) {
			t.Fatalf("recovery did not complete: window=%#v attempt=%#v", window, state.ProbeAttempts[binding.Instance])
		}
		time.Sleep(time.Millisecond)
	}
}

func assertNoActivation(t *testing.T, host *sequenceProbeHost) {
	t.Helper()
	host.mu.Lock()
	defer host.mu.Unlock()
	for _, req := range host.requests {
		if req.Method == http.MethodPost {
			t.Fatalf("unexpected activation or credential POST: %s", req.URL)
		}
	}
}

func TestQuotaSuccessRecoversBlockedSentProbeWithoutResend(t *testing.T) {
	now := time.Date(2026, 9, 30, 5, 0, 0, 0, time.UTC)
	reset := now.Add(2 * time.Hour)
	body := []byte(fmt.Sprintf(`{"rate_limit":{"primary_window":{"used_percent":80,"limit_window_seconds":18000,"reset_at":%q}}}`, reset.Format(time.RFC3339)))
	host := newProbeFixtureHost()
	host.quota = [][]byte{body, body}
	r, binding := blockedProbeFixture(t, now, host, true)
	if err := r.RefreshOnce(); err != nil {
		t.Fatal(err)
	}
	window := waitForAuthRecovery(t, r, binding, func(w ProbeWindow) bool { return w.State == ProbeWaitingReset })
	if !window.Baseline.ResetAt.Equal(reset) || window.Baseline.SuspectedLazy {
		t.Fatalf("old blocked baseline was not replaced: %#v", window)
	}
	current, _ := r.bindings.Lookup("a")
	if current.Login != binding.Login || current.Fingerprint != binding.Fingerprint {
		t.Fatal("recovery changed account login identity")
	}
	assertNoActivation(t, host)
	reloaded, _, err := NewStateStore(r.runtimeStore.path, OSFileHooks(), nil).Load()
	if err != nil || reloaded.Bindings["a"].AuthBlocked || len(reloaded.ProbeAttempts) != 0 {
		t.Fatalf("recovery did not survive restart: state=%#v err=%v", reloaded, err)
	}
}

func TestQuotaSuccessRecoveryKeepsFiveHourTriggerSchedule(t *testing.T) {
	now := time.Date(2026, 9, 30, 5, 0, 0, 0, time.UTC)
	body := []byte(fmt.Sprintf(`{"rate_limit":{"primary_window":{"used_percent":0,"limit_window_seconds":18000,"reset_at":%q}}}`, now.Add(5*time.Hour).Format(time.RFC3339)))
	host := newProbeFixtureHost()
	host.quota = [][]byte{body, body}
	r, binding := blockedProbeFixture(t, now, host, false)
	if err := r.RefreshOnce(); err != nil {
		t.Fatal(err)
	}
	window := waitForAuthRecovery(t, r, binding, func(w ProbeWindow) bool { return w.State == ProbeRetryWait })
	want := time.Date(2026, 9, 30, 9, 0, 0, 0, time.UTC)
	if !window.Deadline.Equal(want) {
		t.Fatalf("next activation=%v, want 17:00 Asia/Shanghai", window.Deadline)
	}
	assertNoActivation(t, host)
}

func TestFailedQuotaRefreshDoesNotRecoverBlockedProbe(t *testing.T) {
	now := time.Date(2026, 9, 30, 5, 0, 0, 0, time.UTC)
	host := newProbeFixtureHost()
	host.quotaStatus = http.StatusUnauthorized
	host.quota = [][]byte{[]byte(`{"error":"unauthorized"}`)}
	r, binding := blockedProbeFixture(t, now, host, true)
	if err := r.RefreshOnce(); err != nil {
		t.Fatal(err)
	}
	state, err := r.runtimeStore.PersistentSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if !state.Bindings["a"].AuthBlocked || state.ProbeWindows[binding.Instance][ProbeWindowFiveHour].State != ProbeAuthBlocked || state.ProbeAttempts[binding.Instance].AttemptID != "old-sent" {
		t.Fatal("failed quota query incorrectly released the blocked attempt")
	}
	assertNoActivation(t, host)
}

func TestProbeAuthRecoveryRejectsStaleAccountAndPreservesFailedCommit(t *testing.T) {
	for _, stale := range []bool{true, false} {
		t.Run(fmt.Sprint(stale), func(t *testing.T) {
			now := time.Date(2026, 9, 30, 5, 0, 0, 0, time.UTC)
			r, binding := blockedProbeFixture(t, now, newProbeFixtureHost(), true)
			before, err := r.runtimeStore.PersistentSnapshot()
			if err != nil {
				t.Fatal(err)
			}
			write := WritebackVersion{Token: binding.ExecutionToken(0), Login: binding.Login, Fingerprint: binding.Fingerprint}
			if stale {
				write.Login++
			} else {
				previous := r.runtimeStore.hooks.Replace
				r.runtimeStore.hooks.Replace = func(src, dst string) error {
					if dst == r.runtimeStore.path {
						return os.ErrPermission
					}
					return previous(src, dst)
				}
				t.Cleanup(func() { r.runtimeStore.hooks.Replace = previous })
			}
			recovered, err := r.recoverProbeAuthFromQuota("a", write, ParsedQuota{}, now)
			if recovered || err == nil || (stale && !errors.Is(err, ErrStaleExecutionToken)) {
				t.Fatalf("recovered=%v err=%v", recovered, err)
			}
			after, err := r.runtimeStore.PersistentSnapshot()
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatalf("rejected recovery changed durable state: err=%v", err)
			}
			current, _ := r.bindings.Lookup("a")
			window, _ := r.probeController.Window(binding.Instance, ProbeWindowFiveHour)
			if !current.AuthBlocked || window.State != ProbeAuthBlocked {
				t.Fatal("rejected recovery changed live state")
			}
		})
	}
}
