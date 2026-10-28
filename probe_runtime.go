package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

type probeReadPayload struct {
	Binding RuntimeBinding
	Windows []ProbeWindowKind
}
type probeReadResult struct {
	Quota                 ParsedQuota
	Credentials           CodexCredentials
	StartedAt, ObservedAt time.Time
	Verified              bool
}
type probeSequencePayload struct {
	Binding RuntimeBinding
	Windows []ProbeWindowKind
	Attempt ProbeAttempt
	// Recovery resumes an attempt whose activation request already left the
	// process. Manual marks a pass an operator asked for through the
	// management API, which relaxes the trigger-time gate only.
	Recovery bool
	Manual   bool
}

// probeSendGate is the resolved clock-gate decision for one probe pass. It is
// evaluated once per decision point so the branch that is taken and the log
// fields that describe it can never disagree.
//
// Gate policy: a manual (operator-issued) trigger IS a trigger, so it satisfies
// the probe_trigger_times gate. It still honours probe_send_windows, which is a
// hard "never send activation requests outside these hours" policy rather than
// a schedule.
type probeSendGate struct {
	Manual           bool
	WeeklyActivation bool
	WindowAllowed    bool
	TriggerAllowed   bool
	Allowed          bool
	SendWindows      string
	TriggerTimes     string
	Timezone         string
	Location         *time.Location
	TriggerMinutes   []int
}

const probeGatePolicy = "manual_bypasses_trigger_times_respects_send_windows"

func (r *QuotaRefresher) evaluateProbeSendGate(now time.Time, manual bool) probeSendGate {
	var cfg Config
	if r != nil && r.state != nil {
		cfg = r.state.Config()
	}
	location := probeSendLocation(cfg.ProbeSendTimezone)
	gate := probeSendGate{
		Manual:         manual,
		WindowAllowed:  probeSendAllowedAt(cfg.ProbeSendWindows, location, now),
		TriggerAllowed: probeTriggerAllowedAt(cfg.ProbeTriggerMinutes, location, now),
		SendWindows:    formatProbeSendWindows(cfg.ProbeSendWindows),
		TriggerTimes:   formatProbeTriggerTimes(cfg.ProbeTriggerMinutes),
		Timezone:       cfg.ProbeSendTimezone,
		Location:       location,
		TriggerMinutes: append([]int(nil), cfg.ProbeTriggerMinutes...),
	}
	gate.Allowed = gate.WindowAllowed && (gate.TriggerAllowed || manual)
	return gate
}

// BypassedTriggerGate reports whether this pass only cleared the gate because
// an operator asked for it outside the configured trigger times. It stays false
// when the send window vetoed the pass anyway: nothing was sent, so no trigger
// time was actually skipped, and a log line claiming otherwise next to
// send_allowed=false would read as a contradiction.
func (g probeSendGate) BypassedTriggerGate() bool {
	return g.Manual && g.Allowed && !g.TriggerAllowed
}

// apply stamps the gate decision onto a log field set. Every value is derived
// from configuration or the clock, so nothing here can carry a credential.
func (g probeSendGate) apply(fields map[string]any) map[string]any {
	if fields == nil {
		fields = map[string]any{}
	}
	fields["manual"] = g.Manual
	fields["send_allowed"] = g.Allowed
	fields["trigger_allowed"] = g.TriggerAllowed
	fields["send_window_allowed"] = g.WindowAllowed
	fields["manual_bypassed_trigger_gate"] = g.BypassedTriggerGate()
	fields["weekly_bypassed_trigger_gate"] = g.WeeklyActivation && g.Allowed && !g.TriggerAllowed
	fields["gate_policy"] = probeGatePolicy
	fields["send_windows"] = g.SendWindows
	fields["trigger_times"] = g.TriggerTimes
	fields["timezone"] = g.Timezone
	return fields
}

// probeFailureDescriptor is the sanitized, enumerated view of a probe failure.
// Only fixed codes and an HTTP status ever leave this type, so no upstream
// body, header, token or cookie can reach a log entry or a management response.
type probeFailureDescriptor struct {
	Code     string
	Category string
	Status   int
}

func classifyProbeFailure(err error) probeFailureDescriptor {
	descriptor := probeFailureDescriptor{Code: "probe_operation_failed", Category: "external_callback"}
	var status quotaStatusError
	var activation probeActivationError
	switch {
	case errors.As(err, &activation):
		descriptor.Code = activation.Code
		descriptor.Category = "upstream_business"
		descriptor.Status = activation.Status
	case errors.As(err, &status):
		descriptor.Code = "quota_http_status"
		descriptor.Category = "upstream_http"
		descriptor.Status = status.status
	case errors.Is(err, ErrCapabilityB):
		descriptor.Code = "background_not_authorized"
		descriptor.Category = "authorization"
	case errors.Is(err, ErrAccountIdentityUnresolved):
		descriptor.Code = "account_identity_unresolved"
		descriptor.Category = "authorization"
	case errors.Is(err, ErrProvisionalFingerprintMismatch):
		descriptor.Code = "credential_fingerprint_mismatch"
		descriptor.Category = "authorization"
	case errors.Is(err, context.Canceled):
		descriptor.Code = "operation_canceled"
		descriptor.Category = "internal"
	case errors.Is(err, context.DeadlineExceeded):
		descriptor.Code = "operation_deadline_exceeded"
		descriptor.Category = "internal"
	}
	return descriptor
}

// recordProbeScheduleTriggered logs the entry point of a 5h probe pass, for
// both the wall-clock schedule and an operator-issued manual trigger.
func (r *QuotaRefresher) recordProbeScheduleTriggered(now time.Time, gate probeSendGate, armed int, armErr error) {
	if r == nil || r.state == nil {
		return
	}
	fields := gate.apply(map[string]any{
		"armed_instances": armed,
		"sent":            false,
		"at":              formatTime(now),
		"next_trigger_at": formatTime(r.nextProbeScheduleDeadline(now)),
	})
	level := "info"
	message := "已触发 5 小时额度周期探测排程"
	if gate.Manual {
		message = "已按管理接口请求手动触发一次 5 小时额度周期探测"
	}
	if armErr != nil {
		level = "warn"
		fields["error"] = "probe_schedule_persist_failed"
		fields["error_category"] = "internal"
	}
	r.state.RecordLog(level, "probe.schedule_triggered", message, fields, now)
}

// beginManualProbe is the manual-trigger dedupe latch: at most one operator
// pass may be in flight, so a double-click cannot queue two activation rounds.
//
// The latch bounds concurrency only. The manual flag itself is deliberately NOT
// derived from it: it is passed down the owning call as an argument
// (runProbeDueOnce -> runProbeDuePass -> probeSequencePayload.Manual) so that it
// is lexically scoped to the pass RunManualProbePass actually owns. Reading it
// from shared state instead would let a foreign owner - a scheduled pass
// servicing a rerun, or a recovery pass - observe manual=true merely because an
// unrelated trigger was in flight, and so claim the trigger-time bypass that
// only an operator-owned pass may have.
func (r *QuotaRefresher) beginManualProbe() bool {
	r.probeRunStateMu.Lock()
	defer r.probeRunStateMu.Unlock()
	if r.probeManualDepth > 0 {
		return false
	}
	r.probeManualDepth++
	return true
}

func (r *QuotaRefresher) endManualProbe() {
	r.probeRunStateMu.Lock()
	if r.probeManualDepth > 0 {
		r.probeManualDepth--
	}
	r.probeRunStateMu.Unlock()
}

// ManualProbeTriggerResult reports what one operator-issued probe pass did.
type ManualProbeTriggerResult struct {
	Manual              bool      `json:"manual"`
	Owned               bool      `json:"owned"`
	TriggeredAt         time.Time `json:"triggered_at"`
	ArmedInstances      int       `json:"armed_instances"`
	SendAllowed         bool      `json:"send_allowed"`
	TriggerAllowed      bool      `json:"trigger_allowed"`
	SendWindowAllowed   bool      `json:"send_window_allowed"`
	BypassedTriggerGate bool      `json:"manual_bypassed_trigger_gate"`
	GatePolicy          string    `json:"gate_policy"`
	SendWindows         string    `json:"send_windows,omitempty"`
	TriggerTimes        string    `json:"trigger_times,omitempty"`
	Timezone            string    `json:"timezone,omitempty"`
}

var (
	// ErrProbeTriggerInFlight rejects a second concurrent manual trigger.
	ErrProbeTriggerInFlight = errors.New("manual probe trigger already running")
	// ErrProbeTriggerDisabled rejects a manual trigger while reset probing is off.
	ErrProbeTriggerDisabled = errors.New("reset probe is disabled")
	// ErrProbeTriggerUnavailable reports that no probe runtime is wired up yet.
	ErrProbeTriggerUnavailable = errors.New("probe runtime unavailable")
)

// RunManualProbePass arms the 5h windows and runs one probe pass on behalf of
// an operator. It reuses the scheduled path end to end, so the WAL claim,
// roster/authorization checks and the single-pass probe lock all still apply;
// the only difference is that the activation gate treats this as a trigger.
func (r *QuotaRefresher) RunManualProbePass(ctx context.Context) (ManualProbeTriggerResult, error) {
	if r == nil || r.probeController == nil || r.runtimeStore == nil {
		return ManualProbeTriggerResult{}, ErrProbeTriggerUnavailable
	}
	if !r.resetProbeEnabled() {
		return ManualProbeTriggerResult{}, ErrProbeTriggerDisabled
	}
	if !r.beginManualProbe() {
		return ManualProbeTriggerResult{}, ErrProbeTriggerInFlight
	}
	defer r.endManualProbe()
	now := r.now()
	gate := r.evaluateProbeSendGate(now, true)
	result := ManualProbeTriggerResult{
		Manual:              true,
		TriggeredAt:         now,
		SendAllowed:         gate.Allowed,
		TriggerAllowed:      gate.TriggerAllowed,
		SendWindowAllowed:   gate.WindowAllowed,
		BypassedTriggerGate: gate.BypassedTriggerGate(),
		GatePolicy:          probeGatePolicy,
		SendWindows:         gate.SendWindows,
		TriggerTimes:        gate.TriggerTimes,
		Timezone:            gate.Timezone,
	}
	armed, armErr := r.armScheduledFiveHourChecks()
	result.ArmedInstances = armed
	r.recordProbeScheduleTriggered(now, gate, armed, armErr)
	if armErr != nil {
		return result, armErr
	}
	owned, err := r.runProbeDueOnce(ctx, true)
	result.Owned = owned
	if !owned {
		// Another pass already owns the probe lock, so this call never executed
		// an operator-gated pass: the rerun it flagged is serviced by that owner
		// under the scheduled gate (the manual flag travels with this call, not
		// with the probe), which is exactly the trigger-time bypass the operator
		// asked for and would not get. Answering 202 here would therefore be a
		// false success. Report the conflict instead - the armed windows are already
		// durable and the existing owner still services them, so retrying the
		// trigger costs nothing and sends no extra activation POST.
		r.wakeRefreshLoop()
		if err == nil {
			err = ErrProbeTriggerInFlight
		}
		return result, err
	}
	return result, err
}

func (r *QuotaRefresher) initProbeRuntime() error {
	if r.runtimeStore == nil {
		return nil
	}
	state, err := r.runtimeStore.PersistentSnapshot()
	if err != nil {
		return err
	}
	r.probeController = NewProbeController(r.now())
	r.probeController.Load(state.ProbeWindows)
	r.probeWAL = NewProbeWAL(r.runtimeStore)
	r.probeFence = NewFenceAllocator(r.runtimeStore, state, nil)
	r.coordinator.opts.AllocateReadSeq = r.probeFence.Next
	return r.bootstrapProbeWindows()
}

func (r *QuotaRefresher) bootstrapProbeWindows() error {
	if r.probeController == nil || !r.state.Config().EnableResetProbe {
		return nil
	}
	bindings := map[string]RuntimeBinding{}
	if r.bindings != nil {
		r.bindings.mu.RLock()
		for authID, binding := range r.bindings.bindings {
			bindings[authID] = binding
		}
		r.bindings.mu.RUnlock()
	}
	// The roster-hold mutex is also the Probe controller/persistence
	// linearization boundary. Keep snapshot-and-merge ordered with authoritative
	// reconciliation so a stale bootstrap snapshot cannot resurrect a window.
	r.probeHoldMu.Lock()
	defer r.probeHoldMu.Unlock()
	now := r.now()
	observationInterval := r.probeObservationInterval()
	touched := map[AuthInstanceID]struct{}{}
	for instance := range r.probePersistPending {
		touched[instance] = struct{}{}
	}
	// Registration may load schedule settings after runtime construction.
	// Migrate here under the same lock as all controller/persistence changes.
	if r.runtimeStore != nil {
		persisted, err := r.runtimeStore.PersistentSnapshot()
		if err != nil {
			return err
		}
		persisted.ProbeWindows = r.probeController.Snapshot()
		if rearmScheduledWeeklyWindows(&persisted, r.state.Config(), now) {
			for instance, windows := range persisted.ProbeWindows {
				w, ok := windows[ProbeWindowLong]
				current, exists := r.probeController.Window(instance, ProbeWindowLong)
				if ok && exists && !w.Deadline.Equal(current.Deadline) {
					r.probeController.SetWindow(instance, ProbeWindowLong, w)
					touched[instance] = struct{}{}
				}
			}
		}
	}
	for instance, windows := range r.probeController.Snapshot() {
		for kind, window := range windows {
			if window.State == ProbeConfirmed {
				deadline := confirmedWeeklyDeadline(kind, window.Baseline)
				if !deadline.IsZero() && !window.Deadline.Equal(deadline) {
					window.Deadline = deadline
					r.probeController.SetWindow(instance, kind, window)
					touched[instance] = struct{}{}
				}
				continue
			}
			if window.State != ProbeWaitingReset || window.Baseline.Kind != ProbeBaselineReset || window.Baseline.WindowLength <= 0 {
				continue
			}
			deadline := deadlineFor(window.Baseline, now, observationInterval)
			if window.Deadline.IsZero() || deadline.Before(window.Deadline) {
				window.Deadline = deadline
				r.probeController.SetWindow(instance, kind, window)
				touched[instance] = struct{}{}
			}
		}
	}
	for _, a := range r.state.Snapshot(now).Accounts {
		observedAt := a.LastSuccessAt
		strictObservation := !observedAt.IsZero() && !observedAt.After(now)
		if !strictObservation {
			observedAt = now
		}
		b, ok := bindings[a.AuthID]
		if !ok {
			continue
		}
		for _, pair := range []struct {
			k ProbeWindowKind
			w *QuotaWindow
		}{{ProbeWindowFiveHour, a.Quota.FiveHour}, {ProbeWindowLong, a.Quota.LongWindow}} {
			if pair.w == nil {
				continue
			}
			if existing, ok := r.probeController.Window(b.Instance, pair.k); ok {
				rearmObservedAt := observedAt
				if !strictObservation {
					rearmObservedAt = time.Time{}
				}
				if rearmed, changed := rearmConfirmedProbeWindow(existing, rearmObservedAt, pair.w, now, observationInterval); changed {
					if r.runtimeRoster().Capability != CapabilityA {
						rearmed.State = ProbeWaitingRoster
						rearmed.Deadline = time.Time{}
					}
					r.probeController.SetWindow(b.Instance, pair.k, rearmed)
					touched[b.Instance] = struct{}{}
					continue
				}
				if existing.Baseline.Kind == ProbeBaselineReset && existing.Baseline.WindowLength == 0 {
					if duration, durationKnown := probeWindowDuration(*pair.w); durationKnown {
						existing.Baseline.WindowLength = duration
						if existing.Baseline.WindowKind == "" {
							existing.Baseline.WindowKind = pair.w.Kind
						}
						if strictObservation && looksLikeStrictLazyObservation(observedAt, *pair.w, duration) {
							existing.Baseline.ResetAt = pair.w.ResetAt
							existing.Baseline.Usage = *pair.w.UsedPercent
							existing.Baseline.SuspectedLazy = true
							existing.State = ProbePendingCheck
							existing.Deadline = time.Time{}
						} else if existing.State == ProbeWaitingReset {
							existing.Deadline = deadlineFor(existing.Baseline, now, observationInterval)
							if !existing.Deadline.After(now) {
								existing.State = ProbePendingCheck
								existing.Deadline = time.Time{}
							}
						}
						if r.runtimeRoster().Capability != CapabilityA {
							existing.State = ProbeWaitingRoster
							existing.Deadline = time.Time{}
						}
						r.probeController.SetWindow(b.Instance, pair.k, existing)
						touched[b.Instance] = struct{}{}
					}
				}
				continue
			}
			usage := 0.0
			if pair.w.UsedPercent != nil {
				usage = *pair.w.UsedPercent
			}
			duration, durationKnown := probeWindowDuration(*pair.w)
			base := ResetProbeBaseline(pair.w.ResetAt, usage, 0)
			base.WindowKind = pair.w.Kind
			if durationKnown {
				base.WindowLength = duration
			}
			state := ProbeWaitingReset
			deadline := deadlineFor(base, now, observationInterval)
			lazy := false
			if strictObservation {
				_, lazy = firstObservationLazyWindow(observedAt, *pair.w)
			}
			if lazy {
				base.SuspectedLazy = true
				state = ProbePendingCheck
				deadline = time.Time{}
			} else if !deadline.After(now) {
				state = ProbePendingCheck
				deadline = time.Time{}
			}
			if r.runtimeRoster().Capability != CapabilityA {
				state = ProbeWaitingRoster
				deadline = time.Time{}
			}
			r.probeController.SetWindow(b.Instance, pair.k, ProbeWindow{State: state, Baseline: base, Deadline: deadline})
			touched[b.Instance] = struct{}{}
		}
	}
	err := r.persistProbeInstances(touched)
	if err != nil {
		if r.probePersistPending == nil {
			r.probePersistPending = map[AuthInstanceID]struct{}{}
		}
		for instance := range touched {
			r.probePersistPending[instance] = struct{}{}
		}
	} else {
		for instance := range touched {
			delete(r.probePersistPending, instance)
		}
	}
	if err == nil && len(touched) > 0 {
		r.wakeRefreshLoop()
	}
	return err
}

func (r *QuotaRefresher) probeObservationInterval() time.Duration {
	interval := NormalizeConfig(r.state.Config()).QuotaRefreshInterval
	if interval < probeUnknownResetRecheck {
		return probeUnknownResetRecheck
	}
	return interval
}

func (r *QuotaRefresher) probeScheduleConfig() ([]int, *time.Location, string) {
	if r == nil || r.state == nil {
		return nil, time.Local, ""
	}
	cfg := r.state.Config()
	minutes := append([]int(nil), cfg.ProbeTriggerMinutes...)
	loc := probeSendLocation(cfg.ProbeSendTimezone)
	key := cfg.ProbeSendTimezone + "|" + formatProbeTriggerTimes(minutes)
	return minutes, loc, key
}

func (r *QuotaRefresher) nextProbeScheduleDeadline(now time.Time) time.Time {
	minutes, loc, key := r.probeScheduleConfig()
	if len(minutes) == 0 {
		return time.Time{}
	}
	r.probeScheduleMu.Lock()
	defer r.probeScheduleMu.Unlock()
	if r.probeScheduleKey != key || r.probeNextTrigger.IsZero() {
		r.probeScheduleKey = key
		r.probeNextTrigger = nextProbeTriggerAt(minutes, loc, now)
	}
	return r.probeNextTrigger
}

func (r *QuotaRefresher) consumeProbeSchedule(now time.Time) bool {
	minutes, loc, key := r.probeScheduleConfig()
	if len(minutes) == 0 {
		return false
	}
	r.probeScheduleMu.Lock()
	defer r.probeScheduleMu.Unlock()
	if r.probeScheduleKey != key || r.probeNextTrigger.IsZero() {
		r.probeScheduleKey = key
		r.probeNextTrigger = nextProbeTriggerAt(minutes, loc, now)
		return false
	}
	if now.Before(r.probeNextTrigger) {
		return false
	}
	r.probeNextTrigger = nextProbeTriggerAt(minutes, loc, r.probeNextTrigger.Add(time.Nanosecond))
	return true
}

func (r *QuotaRefresher) armScheduledFiveHourChecks() (int, error) {
	if r == nil || r.probeController == nil || r.runtimeStore == nil {
		return 0, nil
	}
	r.probeHoldMu.Lock()
	defer r.probeHoldMu.Unlock()
	touched := map[AuthInstanceID]struct{}{}
	for instance, windows := range r.probeController.Snapshot() {
		window, ok := windows[ProbeWindowFiveHour]
		if !ok {
			continue
		}
		switch window.State {
		case ProbeWaitingReset, ProbeRetryWait, ProbeConfirmed:
			window.State = ProbePendingCheck
			window.Deadline = time.Time{}
			window.AttemptID = ""
			r.probeController.SetWindow(instance, ProbeWindowFiveHour, window)
			touched[instance] = struct{}{}
		}
	}
	return len(touched), r.persistProbeInstances(touched)
}

func (r *QuotaRefresher) persistProbeInstances(instances map[AuthInstanceID]struct{}) error {
	if r.runtimeStore == nil || r.probeController == nil || len(instances) == 0 {
		return nil
	}
	snapshot := r.probeController.Snapshot()
	_, err := r.runtimeStore.Update(func(state *PersistentState) error {
		for instance := range instances {
			if windows, ok := snapshot[instance]; ok {
				state.ProbeWindows[instance] = windows
			} else {
				delete(state.ProbeWindows, instance)
			}
		}
		return nil
	})
	return err
}
func (r *QuotaRefresher) persistProbeWindows() error {
	if r.runtimeStore == nil || r.probeController == nil {
		return nil
	}
	snapshot := r.probeController.Snapshot()
	_, err := r.runtimeStore.Update(func(s *PersistentState) error {
		for instance, windows := range snapshot {
			s.ProbeWindows[instance] = windows
		}
		return nil
	})
	return err
}

func nonterminalProbeAttempt(attempt ProbeAttempt) bool {
	switch attempt.Phase {
	case ProbeAttemptPrepared, ProbeAttemptSending, ProbeAttemptSent, ProbeAttemptSentUnknown:
		return true
	default:
		return false
	}
}

func attemptReferencesWindow(attempt ProbeAttempt, kind ProbeWindowKind) bool {
	for _, candidate := range attempt.Windows {
		if candidate == kind {
			return true
		}
	}
	return false
}

func (r *QuotaRefresher) reconcileObservedProbeWindows(instance AuthInstanceID, quota ParsedQuota) error {
	if r.runtimeStore == nil || r.probeController == nil || instance == 0 {
		return nil
	}
	r.probeHoldMu.Lock()
	defer r.probeHoldMu.Unlock()
	observed := map[ProbeWindowKind]*QuotaWindow{
		ProbeWindowFiveHour: quota.FiveHour,
		ProbeWindowLong:     quota.LongWindow,
	}
	now := r.now()
	observationInterval := r.probeObservationInterval()
	updated, err := r.runtimeStore.Update(func(persisted *PersistentState) error {
		attempt := persisted.ProbeAttempts[instance]
		for kind, observation := range observed {
			window, exists := persisted.ProbeWindows[instance][kind]
			if observation != nil {
				if exists {
					if rearmed, changed := rearmConfirmedProbeWindow(window, now, observation, now, observationInterval); changed {
						persisted.ProbeWindows[instance][kind] = rearmed
					}
				}
				continue
			}
			if window.State == ProbeConfirmed || (nonterminalProbeAttempt(attempt) && attemptReferencesWindow(attempt, kind)) {
				continue
			}
			delete(persisted.ProbeWindows[instance], kind)
			if len(persisted.ProbeWindows[instance]) == 0 {
				delete(persisted.ProbeWindows, instance)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	for kind := range observed {
		if window, retained := updated.ProbeWindows[instance][kind]; retained {
			r.probeController.SetWindow(instance, kind, window)
		} else {
			r.probeController.RemoveWindow(instance, kind)
		}
	}
	r.wakeRefreshLoop()
	return nil
}

// 仅接受当前账号版本的成功额度查询，不用业务反馈或旧缓存解除认证阻断。
func (r *QuotaRefresher) recoverProbeAuthFromQuota(authID string, write WritebackVersion, quota ParsedQuota, observedAt time.Time) (bool, error) {
	if r.bindings == nil || r.runtimeStore == nil || r.probeController == nil || observedAt.IsZero() || observedAt.After(r.now()) {
		return false, nil
	}
	r.bindings.mu.Lock()
	defer r.bindings.mu.Unlock()
	binding, ok := r.bindings.bindings[authID]
	if !ok || !ValidateWriteback(BindingVersion{Instance: binding.Instance, Admission: binding.Admission, Tier: TierGeneration(binding.Generation), Login: binding.Login, Fingerprint: binding.Fingerprint}, write) {
		return false, ErrStaleExecutionToken
	}
	r.probeHoldMu.Lock()
	defer r.probeHoldMu.Unlock()
	blocked := binding.AuthBlocked
	for _, window := range r.probeController.Snapshot()[binding.Instance] {
		blocked = blocked || window.State == ProbeAuthBlocked
	}
	if !blocked {
		return false, nil
	}
	snapshots := probeSnapshots(quota)
	committed, err := r.runtimeStore.UpdateMirrored(func(state *PersistentState) error {
		current, ok := state.Bindings[authID]
		if !ok || !ValidateWriteback(BindingVersion{Instance: current.Instance, Admission: current.Admission, Tier: TierGeneration(current.Generation), Login: current.Login, Fingerprint: current.Fingerprint}, write) {
			return ErrStaleExecutionToken
		}
		current.AuthBlocked = false
		state.Bindings[authID] = current
		attempt := state.ProbeAttempts[binding.Instance]
		for kind, window := range state.ProbeWindows[binding.Instance] {
			if window.State != ProbeAuthBlocked {
				continue
			}
			// 用本次观测替换过期基线，避免数日前的时间差反复触发异常暂停。
			if snap, ok := snapshots[kind]; ok && snap.Valid && snap.Usage != nil {
				window.Baseline = ClassifyProbeWindow(ProbeBaseline{}, snap, observedAt).Baseline
				if snap.ResetAt != nil && snap.WindowLengthKnown {
					observation := QuotaWindow{Kind: snap.WindowKind, UsedPercent: snap.Usage, ResetAt: *snap.ResetAt}
					window.Baseline.SuspectedLazy = looksLikeStrictLazyObservation(observedAt, observation, snap.WindowLength)
				}
			}
			window.State = ProbePendingCheck
			window.Deadline = time.Time{}
			window.AuthBlockedAtLogin = 0
			window.RetryCount = 0
			window.AttemptID = ""
			switch attempt.Phase {
			case ProbeAttemptSending, ProbeAttemptSent, ProbeAttemptSentUnknown:
				if attemptReferencesWindow(attempt, kind) {
					// 保留发送日志和屏障；未知结果必须只读恢复，不能重新发送。
					window.State = ProbeSentUnknown
					window.AttemptID = attempt.AttemptID
				}
			}
			state.ProbeWindows[binding.Instance][kind] = window
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	r.bindings.bindings = committed.Bindings
	r.syncProbeControllerInstance(binding.Instance, committed)
	return true, nil
}

func rearmConfirmedProbeWindow(window ProbeWindow, observedAt time.Time, observation *QuotaWindow, now time.Time, observationInterval time.Duration) (ProbeWindow, bool) {
	if window.State != ProbeConfirmed || observation == nil || observation.UsedPercent == nil || observation.ResetAt.IsZero() || observedAt.IsZero() || observedAt.After(now) {
		return window, false
	}
	duration, durationKnown := probeWindowDuration(*observation)
	if !durationKnown || duration <= 0 {
		return window, false
	}
	if window.Baseline.Kind == ProbeBaselineReset && !window.Baseline.ResetAt.IsZero() && !observation.ResetAt.After(window.Baseline.ResetAt.Add(probeSkewTolerance)) {
		return window, false
	}
	base := ResetProbeBaseline(observation.ResetAt, *observation.UsedPercent, duration)
	base.WindowKind = observation.Kind
	window.Baseline = base
	window.AttemptID = ""
	window.RetryCount = 0
	if looksLikeStrictLazyObservation(observedAt, *observation, duration) {
		window.Baseline.SuspectedLazy = true
		window.State = ProbePendingCheck
		window.Deadline = time.Time{}
	} else {
		window.State = ProbeWaitingReset
		window.Deadline = deadlineFor(window.Baseline, now, observationInterval)
	}
	return window, true
}

func (r *QuotaRefresher) syncProbeControllerInstance(instance AuthInstanceID, state PersistentState) {
	if r.probeController == nil {
		return
	}
	r.probeController.ReplaceInstance(instance, state.ProbeWindows[instance])
}

func (r *QuotaRefresher) syncProbeControllerInstanceFromStore(instance AuthInstanceID) {
	if r.runtimeStore == nil {
		return
	}
	state, err := r.runtimeStore.PersistentSnapshot()
	if err == nil {
		r.syncProbeControllerInstance(instance, state)
	}
}

func (r *QuotaRefresher) persistTerminalProbeCompletion(instance AuthInstanceID, attemptID string, quota ParsedQuota, phases ...ProbeAttemptPhase) error {
	if r.runtimeStore == nil || r.probeController == nil || instance == 0 {
		return nil
	}
	r.probeHoldMu.Lock()
	defer r.probeHoldMu.Unlock()
	return r.persistTerminalProbeCompletionLocked(instance, attemptID, quota, phases...)
}

func (r *QuotaRefresher) persistVerifiedProbeCompletion(instance AuthInstanceID, attemptID string, sendStartedAt, sendCompletedAt time.Time, quota ParsedQuota, phases ...ProbeAttemptPhase) error {
	if r.runtimeStore == nil || r.probeController == nil || instance == 0 {
		return nil
	}
	r.probeHoldMu.Lock()
	defer r.probeHoldMu.Unlock()
	r.probeController.Advance(instance, ProbeEvent{Kind: ProbeEventVerifyResult, Now: r.now(), SendStartedAt: sendStartedAt, SendCompletedAt: sendCompletedAt, Snapshots: probeSnapshots(quota)})
	return r.persistTerminalProbeCompletionLocked(instance, attemptID, quota, phases...)
}

func (r *QuotaRefresher) persistTerminalProbeCompletionLocked(instance AuthInstanceID, attemptID string, quota ParsedQuota, phases ...ProbeAttemptPhase) error {
	observed := map[ProbeWindowKind]bool{
		ProbeWindowFiveHour: quota.FiveHour != nil,
		ProbeWindowLong:     quota.LongWindow != nil,
	}
	controllerWindows := r.probeController.Snapshot()[instance]
	windows := make(map[ProbeWindowKind]ProbeWindow, len(controllerWindows))
	for kind, window := range controllerWindows {
		windows[kind] = window
	}
	for kind, present := range observed {
		if present {
			continue
		}
		delete(windows, kind)
	}
	_, err := r.runtimeStore.Update(func(persisted *PersistentState) error {
		if _, err := exactProbeAttempt(persisted, instance, attemptID, phases...); err != nil {
			return err
		}
		if len(windows) > 0 {
			persisted.ProbeWindows[instance] = windows
		} else {
			delete(persisted.ProbeWindows, instance)
		}
		delete(persisted.ProbeAttempts, instance)
		return nil
	})
	if err != nil {
		r.syncProbeControllerInstanceFromStore(instance)
		return err
	}
	for kind, present := range observed {
		if !present {
			r.probeController.RemoveWindow(instance, kind)
		}
	}
	return nil
}

func (r *QuotaRefresher) persistProbeFailure(instance AuthInstanceID, attemptID string, windows []ProbeWindowKind, sent, authBlocked bool, login LoginEpoch, suppressUntil time.Time) error {
	if r.runtimeStore == nil || r.probeController == nil || instance == 0 {
		return nil
	}
	r.probeHoldMu.Lock()
	defer r.probeHoldMu.Unlock()
	controllerWindows := r.probeController.Snapshot()[instance]
	now := r.now()
	committed, err := r.runtimeStore.Update(func(state *PersistentState) error {
		var attempt ProbeAttempt
		var attemptErr error
		if sent {
			attempt, attemptErr = exactProbeAttempt(state, instance, attemptID, ProbeAttemptSending, ProbeAttemptSent, ProbeAttemptSentUnknown)
		} else {
			attempt, attemptErr = exactProbeAttempt(state, instance, attemptID, ProbeAttemptPrepared, ProbeAttemptSending)
		}
		if attemptErr != nil {
			return attemptErr
		}
		if sent {
			attempt.Phase = ProbeAttemptSentUnknown
			if suppressUntil.After(attempt.SuppressUntil) {
				attempt.SuppressUntil = suppressUntil
			}
			state.ProbeAttempts[instance] = attempt
		} else if attempt.Phase == ProbeAttemptPrepared {
			delete(state.ProbeAttempts, instance)
		}

		next := make(map[ProbeWindowKind]ProbeWindow, len(state.ProbeWindows[instance]))
		for kind, window := range state.ProbeWindows[instance] {
			next[kind] = window
		}
		for _, kind := range windows {
			window, ok := controllerWindows[kind]
			if !ok {
				window, ok = next[kind]
			}
			if !ok || window.State == ProbeWaitingRoster {
				continue
			}
			if authBlocked {
				window.State = ProbeAuthBlocked
				window.AuthBlockedAtLogin = login
				window.Deadline = time.Time{}
			} else {
				if sent {
					window.State = ProbeSentUnknown
					window.AttemptID = attemptID
				} else {
					window.State = ProbeRetryWait
					window.AttemptID = ""
				}
				window.RetryCount++
				if sent {
					// A request may have reached the upstream even when its response
					// was lost; recovery must verify it rather than resend it.
					window.Deadline = now.Add(probeBackoff(window.RetryCount))
				} else {
					cfg := r.state.Config()
					window.Deadline = probeWindowFailureDeadline(kind, window.Baseline, cfg, now, window.RetryCount)
				}
			}
			next[kind] = window
		}
		if len(next) > 0 {
			state.ProbeWindows[instance] = next
		} else {
			delete(state.ProbeWindows, instance)
		}
		return nil
	})
	if err != nil {
		r.syncProbeControllerInstanceFromStore(instance)
		return err
	}
	r.syncProbeControllerInstance(instance, committed)
	return nil
}

func (r *QuotaRefresher) reconcileProbeOrphans(persisted PersistentState, active map[AuthInstanceID]struct{}) error {
	keys := map[AuthInstanceID]struct{}{}
	for i := range persisted.ProbeWindows {
		keys[i] = struct{}{}
	}
	for i := range persisted.ProbeAttempts {
		keys[i] = struct{}{}
	}
	var firstErr error
	for i := range keys {
		if _, ok := active[i]; ok {
			continue
		}
		r.probeController.Advance(i, ProbeEvent{Kind: ProbeEventInstanceRemoved, Now: r.now()})
		_, err := r.runtimeStore.Update(func(s *PersistentState) error { delete(s.ProbeWindows, i); delete(s.ProbeAttempts, i); return nil })
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (r *QuotaRefresher) holdProbeForRoster() error {
	if r.runtimeStore == nil || r.probeController == nil {
		return nil
	}
	snapshot := r.probeController.Snapshot()
	committed, err := r.runtimeStore.Update(func(s *PersistentState) error {
		for instance, windows := range snapshot {
			attempt, hasAttempt := s.ProbeAttempts[instance]
			sent := hasAttempt && (attempt.Phase == ProbeAttemptSending || attempt.Phase == ProbeAttemptSent || attempt.Phase == ProbeAttemptSentUnknown)
			sentWindows := make(map[ProbeWindowKind]struct{}, len(attempt.Windows))
			if sent {
				for _, kind := range attempt.Windows {
					sentWindows[kind] = struct{}{}
				}
			} else if hasAttempt {
				delete(s.ProbeAttempts, instance)
			}
			next := make(map[ProbeWindowKind]ProbeWindow, len(windows))
			for kind, window := range windows {
				window.Deadline = time.Time{}
				if _, belongsToSentAttempt := sentWindows[kind]; belongsToSentAttempt {
					window.State = ProbeSentUnknown
					window.AttemptID = attempt.AttemptID
				} else if window.State != ProbeConfirmed {
					window.State = ProbeWaitingRoster
					window.AttemptID = ""
				}
				next[kind] = window
			}
			if len(next) > 0 {
				s.ProbeWindows[instance] = next
			} else {
				delete(s.ProbeWindows, instance)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	for instance := range snapshot {
		r.syncProbeControllerInstance(instance, committed)
	}
	return err
}

func (r *QuotaRefresher) persistProbeRosterHold() error {
	r.probeHoldMu.Lock()
	defer r.probeHoldMu.Unlock()
	err := r.holdProbeForRoster()
	r.probeHoldPending = err != nil
	r.probeHoldErr = err
	return err
}

func (r *QuotaRefresher) retryProbeRosterHold() error {
	r.probeHoldMu.Lock()
	pending := r.probeHoldPending
	r.probeHoldMu.Unlock()
	if !pending {
		return nil
	}
	return r.persistProbeRosterHold()
}

func (r *QuotaRefresher) recoverProbeFromRoster(bindings map[string]RuntimeBinding) error {
	if r.runtimeStore == nil || r.probeController == nil {
		return nil
	}
	now := r.now()
	touched := make(map[AuthInstanceID]struct{}, len(bindings))
	for _, binding := range bindings {
		touched[binding.Instance] = struct{}{}
		r.probeController.Advance(binding.Instance, ProbeEvent{Kind: ProbeEventRosterConfirmed, Now: now, ObservationInterval: r.probeObservationInterval()})
		for _, kind := range []ProbeWindowKind{ProbeWindowFiveHour, ProbeWindowLong} {
			if window, ok := r.probeController.Window(binding.Instance, kind); ok && window.State == ProbeAuthBlocked && binding.Login > window.AuthBlockedAtLogin {
				window.State = ProbePendingCheck
				window.Deadline = time.Time{}
				r.probeController.SetWindow(binding.Instance, kind, window)
			}
			window, ok := r.probeController.Window(binding.Instance, kind)
			if ok && window.State == ProbeWaitingReset && !window.Deadline.After(now) {
				window.State = ProbePendingCheck
				window.Deadline = time.Time{}
				r.probeController.SetWindow(binding.Instance, kind, window)
			}
		}
	}
	return r.persistProbeInstances(touched)
}

func activeProbeBindings(roster HostRosterSnapshot, bindings map[string]RuntimeBinding) (map[string]RuntimeBinding, map[AuthInstanceID]struct{}) {
	tier := highestTierSet(roster)
	byID := map[string]RuntimeBinding{}
	instances := map[AuthInstanceID]struct{}{}
	for id, b := range bindings {
		if _, ok := tier[id]; ok && b.Instance != 0 {
			byID[id] = b
			instances[b.Instance] = struct{}{}
		}
	}
	return byID, instances
}

func (r *QuotaRefresher) RunProbeDueOnce(ctx context.Context) error {
	_, err := r.runProbeDueOnce(ctx, false)
	return err
}

// runProbeDueOnce runs one due-probe pass. manual marks a pass an operator
// asked for through the management API; it stays with this call and is never
// inherited by another goroutine's pass.
func (r *QuotaRefresher) runProbeDueOnce(ctx context.Context, manual bool) (bool, error) {
	return r.runProbeDueOnceWithAdmission(ctx, nil, manual)
}

func (r *QuotaRefresher) runProbeDueOnceAdmitted(ctx context.Context, generation uint64) (bool, error) {
	return r.runProbeDueOnceWithAdmission(ctx, &generation, false)
}

func (r *QuotaRefresher) runProbeDueOnceWithAdmission(ctx context.Context, generation *uint64, manual bool) (bool, error) {
	if !r.resetProbeEnabled() {
		return false, nil
	}
	r.probeRunStateMu.Lock()
	if !r.probeRunMu.TryLock() {
		r.probeRerunPending = true
		r.probeRunStateMu.Unlock()
		return false, nil
	}
	if generation != nil && !r.probeLaunchAdmissionCurrentLocked(*generation) {
		r.probeRunMu.Unlock()
		r.probeRunStateMu.Unlock()
		return false, nil
	}
	r.probeRerunPending = false
	r.probeRunStateMu.Unlock()
	var firstErr error
	for {
		err := r.runProbeDuePass(ctx, manual)
		if firstErr == nil {
			firstErr = err
		}
		if err != nil {
			r.finishProbeOwnerError(true)
			return true, firstErr
		}
		r.probeRunStateMu.Lock()
		if r.probeRerunPending {
			r.probeRerunPending = false
			r.probeRunStateMu.Unlock()
			continue
		}
		r.probeRunMu.Unlock()
		r.probeRunStateMu.Unlock()
		return true, firstErr
	}
}

func (r *QuotaRefresher) runProbeDuePass(ctx context.Context, manual bool) error {
	if !r.resetProbeEnabled() {
		return nil
	}
	if err := r.retryProbeRosterHold(); err != nil {
		return err
	}
	refresherMu.Lock()
	rosterController := globalRosterController
	refresherMu.Unlock()
	if rosterController != nil {
		_, _ = rosterController.WakeForProbe(ctx)
	}
	if !r.probeBackgroundAllowed() {
		return ErrCapabilityB
	}
	if r.runtimeRoster().Provisional {
		if !r.provisionalProbeRiskConfigured() || !r.consumeProvisionalPermit() {
			return ErrCapabilityB
		}
	}
	if r.probeController == nil {
		return errors.New("probe runtime unavailable")
	}
	if err := r.bootstrapProbeWindows(); err != nil {
		return err
	}
	now := r.now()
	persisted, err := r.runtimeStore.PersistentSnapshot()
	if err != nil {
		return err
	}
	r.bindings.mu.RLock()
	bindings := make(map[string]RuntimeBinding, len(r.bindings.bindings))
	for id, b := range r.bindings.bindings {
		bindings[id] = b
	}
	r.bindings.mu.RUnlock()
	bindings, activeInstances := activeProbeBindings(r.runtimeRoster(), bindings)
	var firstErr error
	if err := r.reconcileProbeOrphans(persisted, activeInstances); err != nil {
		firstErr = err
	}
	for authID, b := range bindings {
		if attempt, ok := persisted.ProbeAttempts[b.Instance]; ok && (attempt.Phase == ProbeAttemptSending || attempt.Phase == ProbeAttemptSent || attempt.Phase == ProbeAttemptSentUnknown) {
			continue // recovery owns every nonterminal send, suppression expiry never authorizes resend
		}
		if b.AuthBlocked {
			for _, k := range []ProbeWindowKind{ProbeWindowFiveHour, ProbeWindowLong} {
				if w, ok := r.probeController.Window(b.Instance, k); ok {
					w.State = ProbeAuthBlocked
					w.AuthBlockedAtLogin = b.Login
					r.probeController.SetWindow(b.Instance, k, w)
				}
			}
			continue
		}
		for _, k := range []ProbeWindowKind{ProbeWindowFiveHour, ProbeWindowLong} {
			if w, ok := r.probeController.Window(b.Instance, k); ok && w.State == ProbeAuthBlocked && b.Login > w.AuthBlockedAtLogin {
				w.State = ProbePendingCheck
				w.Deadline = time.Time{}
				r.probeController.SetWindow(b.Instance, k, w)
			}
		}
		var due []ProbeWindowKind
		for _, k := range []ProbeWindowKind{ProbeWindowFiveHour, ProbeWindowLong} {
			if w, ok := r.probeController.Window(b.Instance, k); ok && !w.Deadline.IsZero() && !w.Deadline.After(now) && w.State != ProbePendingCheck {
				r.probeController.Advance(b.Instance, ProbeEvent{Kind: ProbeEventDeadline, Window: k, Now: now})
			}
			if w, ok := r.probeController.Window(b.Instance, k); ok && w.State == ProbePendingCheck {
				due = append(due, k)
			}
		}
		if len(due) == 0 {
			continue
		}
		var attempt ProbeAttempt
		claimWindows := r.probeController.Snapshot()[b.Instance]
		claimed, claimErr := r.runtimeStore.Update(func(s *PersistentState) error {
			if existing, ok := s.ProbeAttempts[b.Instance]; ok && existing.AttemptID != "" {
				attempt = existing
				return nil
			}
			s.ProbeAttemptSeq++
			attempt = ProbeAttempt{Instance: b.Instance, AttemptID: fmt.Sprintf("probe-%d-%d", b.Instance, s.ProbeAttemptSeq), Windows: append([]ProbeWindowKind(nil), due...), Phase: ProbeAttemptPrepared, CreatedAt: now, VerifyNotBefore: now}
			s.ProbeAttempts[b.Instance] = attempt
			if claimWindows != nil {
				s.ProbeWindows[b.Instance] = claimWindows
			} else {
				delete(s.ProbeWindows, b.Instance)
			}
			return nil
		})
		if claimErr != nil {
			if firstErr == nil {
				firstErr = claimErr
			}
			continue
		}
		if claimed.ProbeAttempts[b.Instance].AttemptID != attempt.AttemptID || attempt.Phase != ProbeAttemptPrepared {
			continue
		}
		result := r.coordinator.SubmitTyped(Intent{AuthID: authID, Instance: b.Instance, Generation: TierGeneration(b.Generation), Class: OperationProbeSequence, Source: SourceProbeActivation, AttemptID: attempt.AttemptID, Token: b.ExecutionToken(0), Login: b.Login, Fingerprint: b.Fingerprint, Payload: probeSequencePayload{Binding: b, Windows: due, Attempt: attempt, Manual: manual}}).Await(ctx)
		if result.Err != nil {
			if firstErr == nil {
				firstErr = result.Err
			}
			continue
		}
	}
	return firstErr
}

func (r *QuotaRefresher) RunProbeRecoveryOnce(ctx context.Context) error {
	if !r.resetProbeEnabled() {
		return nil
	}
	r.probeRunMu.Lock()
	return r.runProbeRecoveryOwned(ctx)
}

func (r *QuotaRefresher) runProbeRecoveryOnceAdmitted(ctx context.Context, generation uint64) (bool, error) {
	if !r.resetProbeEnabled() {
		return false, nil
	}
	r.probeRunMu.Lock()
	r.probeRunStateMu.Lock()
	if !r.probeLaunchAdmissionCurrentLocked(generation) {
		r.probeRunMu.Unlock()
		r.probeRunStateMu.Unlock()
		return false, nil
	}
	r.probeRunStateMu.Unlock()
	return true, r.runProbeRecoveryOwned(ctx)
}

func (r *QuotaRefresher) runProbeRecoveryOwned(ctx context.Context) (runErr error) {
	defer func() {
		if runErr != nil {
			r.finishProbeOwnerError(true)
			return
		}
		runErr = r.finishProbeRecoveryOwner(ctx)
	}()
	if err := r.retryProbeRosterHold(); err != nil {
		return err
	}
	refresherMu.Lock()
	rosterController := globalRosterController
	refresherMu.Unlock()
	if rosterController != nil {
		_, _ = rosterController.WakeForProbe(ctx)
	}
	if !r.probeBackgroundAllowed() {
		return ErrCapabilityB
	}
	if r.runtimeRoster().Provisional {
		if !r.provisionalProbeRiskConfigured() || !r.consumeProvisionalPermit() {
			return ErrCapabilityB
		}
	}
	if r.probeWAL == nil || r.probeController == nil {
		return nil
	}
	if err := r.recoverPreparedProbeAttempts(); err != nil {
		return err
	}
	intents, err := r.probeWAL.RecoverChecked(r.now())
	if err != nil {
		return err
	}
	r.bindings.mu.RLock()
	allBindings := make(map[string]RuntimeBinding, len(r.bindings.bindings))
	for id, b := range r.bindings.bindings {
		allBindings[id] = b
	}
	r.bindings.mu.RUnlock()
	bindings, activeInstances := activeProbeBindings(r.runtimeRoster(), allBindings)
	persisted, err := r.runtimeStore.PersistentSnapshot()
	if err != nil {
		return err
	}
	var firstErr error
	touched := map[AuthInstanceID]struct{}{}
	if err = r.reconcileProbeOrphans(persisted, activeInstances); err != nil {
		firstErr = err
	}
	for _, intent := range intents {
		touched[intent.Instance] = struct{}{}
		var authID string
		var binding RuntimeBinding
		for id, b := range bindings {
			if b.Instance == intent.Instance {
				authID, binding = id, b
				break
			}
		}
		if authID == "" || binding.AuthBlocked {
			continue
		}
		windows, _ := intent.Payload.([]ProbeWindowKind)
		intent.AuthID = authID
		intent.Generation = TierGeneration(binding.Generation)
		intent.Class = OperationProbeSequence
		intent.Source = SourceProbeVerify
		intent.Token = binding.ExecutionToken(intent.StartedAfter)
		intent.Login = binding.Login
		intent.Fingerprint = binding.Fingerprint
		st, snapErr := r.runtimeStore.PersistentSnapshot()
		if snapErr != nil {
			if firstErr == nil {
				firstErr = snapErr
			}
			continue
		}
		attempt := st.ProbeAttempts[intent.Instance]
		for _, kind := range attempt.Windows {
			if window, ok := r.probeController.Window(intent.Instance, kind); ok {
				window.State = ProbeSentUnknown
				window.AttemptID = attempt.AttemptID
				window.Deadline = time.Time{}
				r.probeController.SetWindow(intent.Instance, kind, window)
			}
		}
		// Manual is false by construction: recovery resumes an activation another
		// pass already authorized and sends nothing itself, so it must describe
		// that earlier decision rather than borrow a concurrent operator trigger's
		// trigger-time bypass.
		intent.Payload = probeSequencePayload{Binding: binding, Windows: windows, Attempt: attempt, Recovery: true, Manual: false}
		result := r.coordinator.SubmitTyped(intent).Await(ctx)
		if result.Err != nil {
			if firstErr == nil {
				firstErr = result.Err
			}
			continue
		}
	}
	if err := r.persistProbeInstances(touched); err != nil {
		if firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (r *QuotaRefresher) finishProbeRecoveryOwner(ctx context.Context) error {
	for {
		r.probeRunStateMu.Lock()
		if !r.probeRerunPending {
			r.probeRunMu.Unlock()
			r.probeRunStateMu.Unlock()
			return nil
		}
		r.probeRerunPending = false
		r.probeRunStateMu.Unlock()
		if err := r.runProbeDuePass(ctx, false); err != nil {
			r.finishProbeOwnerError(true)
			return err
		}
	}
}

func (r *QuotaRefresher) finishProbeOwnerError(recoverFirst bool) {
	now := time.Now()
	if r.now != nil {
		now = r.now()
	}
	r.probeRunStateMu.Lock()
	if recoverFirst {
		r.probeRecoveryPending = true
	}
	r.publishProbeRetryLocked(now, true)
	r.probeRerunPending = false
	r.probeRunMu.Unlock()
	r.probeRunStateMu.Unlock()
	r.wakeRefreshLoop()
}

func (r *QuotaRefresher) recoverPreparedProbeAttempts() error {
	if r.runtimeStore == nil || r.probeController == nil {
		return nil
	}
	state, err := r.runtimeStore.PersistentSnapshot()
	if err != nil {
		return err
	}
	prepared := map[AuthInstanceID]ProbeAttempt{}
	now := r.now()
	for instance, attempt := range state.ProbeAttempts {
		if attempt.Phase != ProbeAttemptPrepared {
			continue
		}
		prepared[instance] = attempt
		for _, kind := range attempt.Windows {
			window, ok := r.probeController.Window(instance, kind)
			if !ok {
				continue
			}
			window.State = ProbeRetryWait
			window.AttemptID = ""
			window.RetryCount++
			window.Deadline = now
			r.probeController.SetWindow(instance, kind, window)
		}
	}
	if len(prepared) == 0 {
		return nil
	}
	windows := r.probeController.Snapshot()
	_, err = r.runtimeStore.Update(func(persisted *PersistentState) error {
		for instance, attempt := range prepared {
			if instanceWindows, ok := windows[instance]; ok {
				persisted.ProbeWindows[instance] = instanceWindows
			} else {
				delete(persisted.ProbeWindows, instance)
			}
			if current, ok := persisted.ProbeAttempts[instance]; ok && current.AttemptID == attempt.AttemptID && current.Phase == ProbeAttemptPrepared {
				delete(persisted.ProbeAttempts, instance)
			}
		}
		return nil
	})
	return err
}

func (r *QuotaRefresher) runTypedHeld(ctx context.Context, intent Intent, held *HeldLease) OperationResult {
	res := OperationResult{Token: intent.Token, Login: intent.Login, Fingerprint: intent.Fingerprint}
	switch intent.Class {
	case OperationProbeSequence:
		p := intent.Payload.(probeSequencePayload)
		attempt := p.Attempt
		fields := func(windows []ProbeWindowKind) map[string]any {
			return map[string]any{"auth_id": intent.AuthID, "attempt_id": attempt.AttemptID, "windows": append([]ProbeWindowKind(nil), windows...)}
		}
		// activationStatus is the HTTP status of the activation POST, or 0 when
		// no status was ever observed (transport failure, or a recovery pass
		// resuming a send that left in an earlier process).
		activationStatus := 0
		// gateFields is the common shape of every probe lifecycle log entry:
		// who, which attempt, which windows, whether an activation request has
		// already left the process, when, and how the clock gate resolved.
		gateFields := func(gate probeSendGate, windows []ProbeWindowKind, sent bool) map[string]any {
			entry := fields(windows)
			entry["recovery"] = p.Recovery
			entry["sent"] = sent
			entry["at"] = formatTime(r.now())
			if sent {
				// Name the endpoint the activation really used, as a fixed
				// label rather than the URL. activation_http_status is kept
				// separate from http_status because a pass can fail on the
				// verify read long after the activation POST succeeded, and
				// one status field would then describe the wrong request.
				entry["activation_endpoint"] = codexResetProbeEndpointLabel
				if activationStatus != 0 {
					entry["activation_http_status"] = activationStatus
				}
			}
			return gate.apply(entry)
		}
		// sendDecisionGate is the gate that actually authorized the activation
		// POST. Once a request has left the process, every log line describing
		// that attempt must quote this decision rather than re-evaluate the
		// clock: a pass that starts inside an allowed window and fails after
		// the grace boundary would otherwise report sent=true next to
		// send_allowed=false, which reads as a contradiction and as if the send
		// had bypassed the gate. Pre-send entries keep evaluating the clock at
		// the moment they are written, because for them the current decision is
		// the truth.
		var sendDecisionGate *probeSendGate
		eventFields := func(windows []ProbeWindowKind, sent bool) map[string]any {
			if sent && sendDecisionGate != nil {
				return gateFields(*sendDecisionGate, windows, sent)
			}
			return gateFields(r.evaluateProbeSendGate(r.now(), p.Manual), windows, sent)
		}
		recordLog := func(level, event, message string, fields map[string]any) {
			if r.state != nil {
				r.state.RecordLog(level, event, message, fields, r.now())
			}
		}
		read := func() (probeReadResult, error) {
			var auth pluginapi.HostAuthGetResponse
			if err := held.DoHTTP(ctx, func(context.Context) error { var e error; auth, e = r.host.GetAuth(p.Binding.AuthIndex); return e }); err != nil {
				return probeReadResult{}, err
			}
			credentials, err := ExtractCodexCredentials(auth.JSON)
			if err != nil {
				return probeReadResult{}, err
			}
			if credentials.ChatGPTAccountID == "" {
				return probeReadResult{}, ErrAccountIdentityUnresolved
			}
			if NewCredentialFingerprint(credentials.ChatGPTAccountID, credentials.RefreshToken, p.Binding.AuthIndex) != p.Binding.Fingerprint {
				return probeReadResult{}, ErrProvisionalFingerprintMismatch
			}
			started := r.now()
			quota, err := r.typedFetchQuota(ctx, held, credentials)
			return probeReadResult{Quota: quota, Credentials: credentials, StartedAt: started, ObservedAt: r.now()}, err
		}
		recordFailure := func(err error, sent bool, windows []ProbeWindowKind) {
			failureFields := eventFields(windows, sent)
			descriptor := classifyProbeFailure(err)
			failureFields["error"] = descriptor.Code
			failureFields["error_category"] = descriptor.Category
			if descriptor.Status != 0 {
				failureFields["http_status"] = descriptor.Status
			}
			failureFields["failed_at"] = formatTime(r.now())
			recordLog("warn", "probe.failed", "额度周期探测失败，已按安全策略处理", failureFields)
		}
		fail := func(err error, sent bool) OperationResult {
			if r.runtimeRoster().Provisional && (errors.Is(err, ErrProvisionalFingerprintMismatch) || errors.Is(err, ErrCapabilityB)) {
				r.clearProvisionalPermit()
				r.rosterMu.Lock()
				if r.roster.Provisional {
					r.roster.BackgroundAllowed = false
					r.roster.Health = RosterWaiting
				}
				r.rosterMu.Unlock()
				_ = r.persistProbeRosterHold()
				recordFailure(err, sent, p.Windows)
				return OperationResult{Token: intent.Token, Err: err}
			}
			if r.runtimeRoster().Health == RosterFailClosed {
				recordFailure(err, sent, p.Windows)
				return OperationResult{Token: intent.Token, Err: err}
			}
			status, authBlocked := err.(quotaStatusError)
			authBlocked = authBlocked && status.status == http.StatusUnauthorized
			persistErr := r.persistProbeFailure(intent.Instance, attempt.AttemptID, p.Windows, sent, authBlocked, p.Binding.Login, attempt.SuppressUntil)
			if persistErr != nil {
				if !errors.Is(persistErr, ErrProbeAttemptChanged) {
					err = persistErr
				}
			} else if authBlocked && r.bindings != nil {
				if blockErr := r.bindings.MarkAuthBlocked(intent.AuthID); blockErr != nil {
					err = blockErr
				}
			}
			recordFailure(err, sent, p.Windows)
			return OperationResult{Token: intent.Token, Err: err}
		}
		if p.Recovery {
			// The send this recovery resumes was authorized in an earlier pass,
			// at attempt.CreatedAt. Quote the gate as of that instant so the
			// resumed attempt's logs describe the decision that produced the
			// in-flight request, not the clock at recovery time.
			if !attempt.CreatedAt.IsZero() {
				recoveredGate := r.evaluateProbeSendGate(attempt.CreatedAt, p.Manual)
				sendDecisionGate = &recoveredGate
			}
			// A recovery sequence resumes an attempt whose activation request is
			// still in flight, and that request holds the plugin-state read lock
			// for its whole flight (the background-request linearization fence in
			// doBackgroundHTTPRequest). RecordLog takes the same lock for writing,
			// so anything logged here would park this sequence behind an orphaned
			// POST that may never return - including the durable completion commit
			// below, which is what actually retires the attempt. Recovery
			// therefore commits first and only then describes what it did; do not
			// add a log statement above persistVerifiedProbeCompletion.
			if attempt.SendFenceSeq == 0 {
				attempt.SendFenceSeq = intent.StartedAfter
			}
			if attempt.SendFenceSeq == 0 {
				return fail(errors.New("probe recovery missing send fence"), true)
			}
			seq, err := r.probeFence.Next()
			if err != nil {
				return fail(err, true)
			}
			if seq <= attempt.SendFenceSeq {
				return fail(errors.New("verify read did not start after send fence"), true)
			}
			vr, err := read()
			if err != nil {
				return fail(err, true)
			}
			sendCompletedAt := attempt.CreatedAt
			if attempt.SentAt != nil {
				sendCompletedAt = *attempt.SentAt
			}
			if err = r.persistVerifiedProbeCompletion(intent.Instance, attempt.AttemptID, attempt.CreatedAt, sendCompletedAt, vr.Quota, ProbeAttemptSending, ProbeAttemptSent, ProbeAttemptSentUnknown); err != nil {
				recordFailure(err, true, p.Windows)
				return OperationResult{Token: intent.Token, Err: err}
			}
			verifiedFields := eventFields(p.Windows, true)
			verifiedFields["verified_at"] = formatTime(r.now())
			recordLog("info", "probe.verified", "额度周期激活验证完成", verifiedFields)
			res.ReadStartSeq = seq
			vr.Verified = true
			res.Value = vr
			return res
		}
		recordLog("info", "probe.sequence_started", "开始执行额度周期探测流程", eventFields(p.Windows, false))
		recordLog("info", "probe.precheck_started", "开始检查疑似未激活的额度周期", eventFields(p.Windows, false))
		_, err := r.probeFence.Next() // actual-start precheck sequence, distinct from completedFence
		if err != nil {
			return fail(err, false)
		}
		pre, err := read()
		if err != nil {
			return fail(err, false)
		}
		r.probeHoldMu.Lock()
		r.probeController.Advance(intent.Instance, ProbeEvent{Kind: ProbeEventPrecheckResult, Now: r.now(), Snapshots: probeSnapshots(pre.Quota), ObservationInterval: r.probeObservationInterval()})
		var lazy []ProbeWindowKind
		for _, k := range p.Windows {
			if w, ok := r.probeController.Window(intent.Instance, k); ok && w.State == ProbeSentAwaitingVerify {
				w.AttemptID = attempt.AttemptID
				r.probeController.SetWindow(intent.Instance, k, w)
				lazy = append(lazy, k)
			}
		}
		// Clock gate: activation requests are the only quota-consuming step, so
		// they are held back outside the configured send windows. The read-only
		// precheck above still ran, keeping classification state fresh; the
		// window stays lazy and is retried on the next observation cycle, which
		// lands inside an allowed window. Deferring here (rather than skipping
		// the whole probe) reuses the existing WAL-safe "nothing to send" path.
		// A manual trigger clears the trigger-time half of the gate but not the
		// send-window half; see probeSendGate.
		now := r.now()
		gate := r.evaluateProbeSendGate(now, p.Manual)
		gate = gate.withWeeklyActivation(lazy, pre.Quota)
		sendAllowed := gate.Allowed
		sendDecisionGate = &gate
		resultFields := gateFields(gate, p.Windows, false)
		resultFields["lazy_windows"] = append([]ProbeWindowKind(nil), lazy...)
		resultFields["activation_required"] = len(lazy) > 0
		resultFields["checked_at"] = formatTime(now)
		recordLog("info", "probe.precheck_result", "额度周期只读检查完成", resultFields)
		if !sendAllowed && len(lazy) > 0 {
			deferUntil := now.Add(r.probeObservationInterval())
			if next := nextProbeTriggerAt(gate.TriggerMinutes, gate.Location, now); !next.IsZero() {
				deferUntil = next
			}
			deferFields := gateFields(gate, lazy, false)
			deferFields["deferred_until"] = formatTime(deferUntil)
			recordLog("info", "probe.send_deferred", "不在允许的激活时段，本次不发激活请求", deferFields)
			for _, k := range lazy {
				if w, ok := r.probeController.Window(intent.Instance, k); ok {
					w.State = ProbeRetryWait
					w.AttemptID = ""
					w.Deadline = deferUntil
					r.probeController.SetWindow(intent.Instance, k, w)
				}
			}
		}
		if len(lazy) == 0 || !sendAllowed {
			err = r.persistTerminalProbeCompletionLocked(intent.Instance, attempt.AttemptID, pre.Quota, ProbeAttemptPrepared)
			r.probeHoldMu.Unlock()
			if err != nil {
				recordFailure(err, false, p.Windows)
				return OperationResult{Token: intent.Token, Err: err}
			}
			pre.Verified = true
			res.Value = pre
			return res
		}
		r.probeHoldMu.Unlock()
		fence, err := r.probeFence.Next()
		if err != nil {
			return fail(err, false)
		}
		attempt.Windows = lazy
		attempt.SendFenceSeq = fence
		attempt.CreatedAt = r.now()
		attempt.VerifyNotBefore = attempt.CreatedAt.Add(3 * time.Second)
		attempt.SuppressUntil = attempt.CreatedAt.Add(10 * time.Minute)
		if err = r.probeWAL.PersistSending(attempt); err != nil {
			return fail(err, false)
		}
		held.MarkProbeSent(attempt.SuppressUntil)
		// Only the status code is retained: the response body and every request
		// header stay inside this closure so no bearer token, account id or
		// upstream cookie can reach a log entry.
		err = held.DoHTTP(ctx, func(context.Context) error {
			return r.probeWAL.ExecuteSend(func() error {
				resp, e := r.doBackgroundHTTPRequest(codexResetProbeRequest(pre.Credentials), true)
				if e != nil {
					return e
				}
				activationStatus = resp.StatusCode
				if resp.StatusCode < 200 || resp.StatusCode >= 300 {
					return quotaStatusError{status: resp.StatusCode, body: resp.Body}
				}
				// stream=true answers are SSE, so upstream can refuse the
				// generation under a 200. Reporting that refusal keeps a
				// business failure visible instead of recording an activation
				// that never happened.
				if code, rejected := codexActivationRejection(resp.Body); rejected {
					return probeActivationError{Code: code, Status: resp.StatusCode}
				}
				return nil
			})
		})
		if err != nil {
			return fail(err, true)
		}
		sentAt := r.now()
		if err = r.probeWAL.PersistSent(intent.Instance, attempt.AttemptID, sentAt); err != nil {
			return fail(err, true)
		}
		sentFields := gateFields(gate, lazy, true)
		sentFields["http_status"] = activationStatus
		sentFields["sent_at"] = formatTime(sentAt)
		recordLog("info", "probe.activation_sent", "已发送极小请求以激活额度周期", sentFields)
		if err = held.WaitPropagation(ctx, probeActivationVerifyDelay); err != nil {
			return fail(err, true)
		}
		seq, err := r.probeFence.Next()
		if err != nil {
			return fail(err, true)
		}
		if seq <= fence {
			return fail(errors.New("verify read did not start after send fence"), true)
		}
		vr, err := read()
		if err != nil {
			return fail(err, true)
		}
		r.probeHoldMu.Lock()
		r.probeController.Advance(intent.Instance, ProbeEvent{Kind: ProbeEventVerifyResult, Now: r.now(), SendStartedAt: attempt.CreatedAt, SendCompletedAt: sentAt, Snapshots: probeSnapshots(vr.Quota)})
		for _, k := range lazy {
			if w, ok := r.probeController.Window(intent.Instance, k); ok && w.State == ProbeRetryWait && w.Deadline.Before(attempt.SuppressUntil) {
				w.Deadline = attempt.SuppressUntil
				r.probeController.SetWindow(intent.Instance, k, w)
			}
		}
		err = r.persistTerminalProbeCompletionLocked(intent.Instance, attempt.AttemptID, vr.Quota, ProbeAttemptSent)
		r.probeHoldMu.Unlock()
		if err != nil {
			recordFailure(err, true, lazy)
			return OperationResult{Token: intent.Token, Err: err}
		}
		verifiedFields := gateFields(gate, lazy, true)
		verifiedFields["http_status"] = activationStatus
		verifiedFields["verified_at"] = formatTime(r.now())
		recordLog("info", "probe.verified", "额度周期激活验证完成", verifiedFields)
		res.ReadStartSeq = seq
		vr.Verified = true
		res.Value = vr
		return res
	case OperationQuotaRead, OperationProbePrecheck, OperationProbeVerify:
		p := intent.Payload.(probeReadPayload)
		var auth pluginapi.HostAuthGetResponse
		err := held.DoHTTP(ctx, func(context.Context) error { var e error; auth, e = r.host.GetAuth(p.Binding.AuthIndex); return e })
		if err != nil {
			res.Err = err
			return res
		}
		credentials, err := ExtractCodexCredentials(auth.JSON)
		if err != nil {
			res.Err = err
			return res
		}
		if credentials.ChatGPTAccountID == "" {
			res.Err = ErrAccountIdentityUnresolved
			return res
		}
		if r.bindings != nil {
			b, ok := r.bindings.Lookup(intent.AuthID)
			if !ok || NewCredentialFingerprint(credentials.ChatGPTAccountID, credentials.RefreshToken, b.AuthIndex) != intent.Fingerprint {
				res.Err = ErrStaleExecutionToken
				return res
			}
		}
		started := r.now()
		quota, err := r.typedFetchQuota(ctx, held, credentials)
		if err != nil {
			if status, ok := err.(quotaStatusError); ok && status.status == http.StatusUnauthorized && r.bindings != nil {
				_ = r.bindings.MarkAuthBlocked(intent.AuthID)
			}
			res.Err = err
			return res
		}
		res.Value = probeReadResult{Quota: quota, Credentials: credentials, StartedAt: started, ObservedAt: r.now(), Verified: true}
	}
	return res
}

func (r *QuotaRefresher) typedFetchQuota(ctx context.Context, held *HeldLease, credentials CodexCredentials) (ParsedQuota, error) {
	if credentials.ChatGPTAccountID == "" {
		return ParsedQuota{}, ErrAccountIdentityUnresolved
	}
	var resp pluginapi.HTTPResponse
	err := held.DoHTTP(ctx, func(context.Context) error {
		var err error
		resp, err = r.doBackgroundHTTPRequest(pluginapi.HTTPRequest{Method: http.MethodGet, URL: r.state.Config().QuotaEndpoint, Headers: http.Header{
			"Authorization": []string{"Bearer " + credentials.AccessToken}, "Chatgpt-Account-Id": []string{credentials.ChatGPTAccountID}, "Content-Type": []string{"application/json"}, "User-Agent": []string{quotaUserAgent},
		}}, true)
		return err
	})
	if err != nil {
		return ParsedQuota{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ParsedQuota{}, quotaStatusError{status: resp.StatusCode, body: resp.Body}
	}
	return ParseCodexUsagePayload(resp.Body, r.now())
}
func probeSnapshots(q ParsedQuota) map[ProbeWindowKind]QuotaSnapshot {
	out := map[ProbeWindowKind]QuotaSnapshot{}
	for _, p := range []struct {
		k ProbeWindowKind
		w *QuotaWindow
	}{{ProbeWindowFiveHour, q.FiveHour}, {ProbeWindowLong, q.LongWindow}} {
		if p.w == nil {
			continue
		}
		var usage *float64
		if p.w.UsedPercent != nil {
			value := *p.w.UsedPercent
			usage = &value
		}
		reset := p.w.ResetAt
		length, lengthKnown := probeWindowDuration(*p.w)
		out[p.k] = QuotaSnapshot{Valid: true, ResetAt: &reset, Usage: usage, WindowKind: p.w.Kind, WindowLength: length, WindowLengthKnown: lengthKnown}
	}
	return out
}
