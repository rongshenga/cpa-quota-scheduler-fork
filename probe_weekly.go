package main

import "time"

// Confirmed weekly windows sleep until their known reset, not a poll interval.
func confirmedWeeklyDeadline(kind ProbeWindowKind, baseline ProbeBaseline) time.Time {
	if kind != ProbeWindowLong || baseline.Kind != ProbeBaselineReset || baseline.WindowKind != WindowWeekly || baseline.ResetAt.IsZero() {
		return time.Time{}
	}
	return baseline.ResetAt.Add(probeRefreshAfterResetDelay)
}

// Only fresh precheck evidence authorizes bypassing the five-hour schedule.
// A shared activation may naturally anchor both windows with one request.
func (g probeSendGate) withWeeklyActivation(lazy []ProbeWindowKind, quota ParsedQuota) probeSendGate {
	if quota.LongWindow == nil || quota.LongWindow.Kind != WindowWeekly {
		return g
	}
	for _, kind := range lazy {
		if kind == ProbeWindowLong {
			g.WeeklyActivation = true
			g.Allowed = g.WindowAllowed
			break
		}
	}
	return g
}

func probeWindowFailureDeadline(kind ProbeWindowKind, baseline ProbeBaseline, cfg Config, now time.Time, retry int) time.Time {
	if kind == ProbeWindowLong && baseline.WindowKind == WindowWeekly {
		return now.Add(15 * time.Minute)
	}
	return probeFailureDeadline(cfg.ProbeTriggerMinutes, cfg.ProbeSendTimezone, now, retry)
}

// Migrate old schedule deferrals only. Never disturb WAL recovery or ordinary
// retry deadlines. A due deadline performs a fresh precheck before any send.
func rearmScheduledWeeklyWindows(state *PersistentState, cfg Config, now time.Time) bool {
	changed := false
	loc := probeSendLocation(cfg.ProbeSendTimezone)
	for instance, windows := range state.ProbeWindows {
		w, ok := windows[ProbeWindowLong]
		if !ok || w.State != ProbeRetryWait || w.Baseline.WindowKind != WindowWeekly || !w.Baseline.SuspectedLazy || w.AttemptID != "" || !w.Deadline.After(now) {
			continue
		}
		if _, exists := state.ProbeAttempts[instance]; exists {
			continue
		}
		local := w.Deadline.In(loc)
		if local.Second() != 0 || local.Nanosecond() != 0 {
			continue
		}
		for _, minute := range cfg.ProbeTriggerMinutes {
			if local.Hour()*60+local.Minute() == minute {
				w.Deadline = now
				windows[ProbeWindowLong] = w
				changed = true
				break
			}
		}
	}
	return changed
}
