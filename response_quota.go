package main

import (
	"bytes"
	"encoding/json"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

type quotaObservation struct {
	Binding               RuntimeBinding
	Quota                 ParsedQuota
	StartedAt, ObservedAt time.Time
	Verified              bool
	Source                string
}

type quotaStream struct {
	observation quotaObservation
	bindings    map[string]RuntimeBinding
	buffer      []byte
	dropping    bool
	chunk       int
}

// 当前帧只在有界内存中拼接；不落盘正文、请求头或凭据。所有拦截回包均为空。
var responseQuotaStreams = struct {
	sync.Mutex
	items map[string]*quotaStream
}{items: make(map[string]*quotaStream)}

func currentQuotaRefresher() *QuotaRefresher {
	refresherMu.Lock()
	defer refresherMu.Unlock()
	return globalRefresher
}

func responseBinding(r *QuotaRefresher, id, index string) (RuntimeBinding, bool) {
	if r == nil || r.bindings == nil || id == "" || index == "" {
		return RuntimeBinding{}, false
	}
	b, ok := r.bindings.Lookup(id)
	return b, ok && b.AuthIndex == index && !b.AuthBlocked && r.state.IsAuthAdmitted(id)
}

func metadataValue(m map[string]any, key string) string { value, _ := m[key].(string); return value }

// 在请求发出前冻结绑定，首个响应到达时不能认领刚刚重新登录的账号。
func handleQuotaRequestStart(raw []byte) ([]byte, error) {
	var req pluginapi.RequestInterceptRequest
	if len(raw) > 4<<20 || json.Unmarshal(raw, &req) != nil || req.RequestID == "" || len(req.RequestID) > 256 {
		return okEnvelope(pluginapi.RequestInterceptResponse{})
	}
	r := currentQuotaRefresher()
	if r == nil || r.bindings == nil || !r.state.Config().EnableUsageFeedback {
		return okEnvelope(pluginapi.RequestInterceptResponse{})
	}
	bindings := make(map[string]RuntimeBinding)
	r.bindings.mu.RLock()
	for id, b := range r.bindings.bindings {
		if !b.AuthBlocked {
			bindings[id] = b
		}
		if len(bindings) > 256 {
			break
		}
	}
	r.bindings.mu.RUnlock()
	if len(bindings) > 256 {
		return okEnvelope(pluginapi.RequestInterceptResponse{})
	}
	now := r.now()
	responseQuotaStreams.Lock()
	for id, item := range responseQuotaStreams.items {
		if now.Sub(item.observation.StartedAt) > 10*time.Minute {
			delete(responseQuotaStreams.items, id)
		}
	}
	if _, exists := responseQuotaStreams.items[req.RequestID]; !exists && len(responseQuotaStreams.items) < 128 {
		responseQuotaStreams.items[req.RequestID] = &quotaStream{bindings: bindings, observation: quotaObservation{StartedAt: now, Source: "response"}, chunk: -1}
	}
	responseQuotaStreams.Unlock()
	return okEnvelope(pluginapi.RequestInterceptResponse{})
}

func boundQuotaStream(id string, b RuntimeBinding) *quotaStream {
	stream := responseQuotaStreams.items[id]
	if stream == nil || stream.bindings[b.AuthID] != b {
		return nil
	}
	if stream.observation.Binding.AuthID != "" && stream.observation.Binding != b {
		return nil
	}
	stream.observation.Binding = b
	return stream
}

func handleQuotaWebSocket(raw []byte) ([]byte, error) {
	var event pluginapi.WebSocketResponseEvent
	if len(raw) > 256<<10 || json.Unmarshal(raw, &event) != nil || event.Provider != "codex" || event.RequestID == "" {
		return okEnvelope(map[string]any{})
	}
	r := currentQuotaRefresher()
	if r == nil || !r.state.Config().EnableUsageFeedback {
		return okEnvelope(map[string]any{})
	}
	index := metadataValue(event.Metadata, "selected_auth_index")
	if index == "" && r.bindings != nil {
		if b, ok := r.bindings.Lookup(event.AuthID); ok {
			index = b.AuthIndex
		}
	}
	b, ok := responseBinding(r, event.AuthID, index)
	if !ok {
		return okEnvelope(map[string]any{})
	}
	now := r.now()
	responseQuotaStreams.Lock()
	stream := boundQuotaStream(event.RequestID, b)
	var observation quotaObservation
	observed := false
	if stream != nil && event.EventType == "codex.rate_limits" {
		if quota, ok := responseEventQuota(append([]byte("data: "), event.Payload...), now); ok {
			stream.observation.Quota = quota
			stream.observation.ObservedAt = now
			observation = stream.observation
			observed = true
		}
	}
	// 失败不能把早先额度帧升级为恢复证明。
	if event.EventType == "response.failed" || event.EventType == "error" {
		delete(responseQuotaStreams.items, event.RequestID)
	}
	responseQuotaStreams.Unlock()
	if observed {
		r.offerQuotaObservation(observation)
	}
	return okEnvelope(map[string]any{})
}

func quotaWindowShifted(a AccountState, q ParsedQuota) bool {
	if a.TemporaryResetAt.IsZero() {
		return false
	}
	for _, pair := range []struct {
		old     time.Time
		current *QuotaWindow
	}{{a.FailureFiveResetAt, q.FiveHour}, {a.FailureLongResetAt, q.LongWindow}} {
		if pair.current != nil && !pair.old.IsZero() && math.Abs(pair.old.Sub(a.TemporaryResetAt).Seconds()) <= 60 && math.Abs(pair.current.ResetAt.Sub(pair.old).Seconds()) > 60 {
			return true
		}
	}
	return false
}

func handleQuotaResponse(raw []byte) ([]byte, error) {
	var req pluginapi.ResponseInterceptRequest
	if len(raw) > 4<<20 || json.Unmarshal(raw, &req) != nil || req.StatusCode < 200 || req.StatusCode >= 300 {
		return okEnvelope(pluginapi.ResponseInterceptResponse{})
	}
	r := currentQuotaRefresher()
	if r == nil || !r.state.Config().EnableUsageFeedback {
		return okEnvelope(pluginapi.ResponseInterceptResponse{})
	}
	b, ok := responseBinding(r, metadataValue(req.Metadata, "selected_auth_id"), metadataValue(req.Metadata, "selected_auth_index"))
	if !ok {
		return okEnvelope(pluginapi.ResponseInterceptResponse{})
	}
	quota, ok := responseHeaderQuota(req.ResponseHeaders, r.now())
	if !ok {
		return okEnvelope(pluginapi.ResponseInterceptResponse{})
	}
	responseQuotaStreams.Lock()
	stream := boundQuotaStream(req.RequestID, b)
	var observation quotaObservation
	if stream != nil {
		stream.observation.Quota = quota
		stream.observation.ObservedAt = r.now()
		observation = stream.observation
	}
	responseQuotaStreams.Unlock()
	if stream != nil {
		r.offerQuotaObservation(observation)
	}
	return okEnvelope(pluginapi.ResponseInterceptResponse{})
}

func handleQuotaStream(raw []byte) ([]byte, error) {
	var req pluginapi.StreamChunkInterceptRequest
	if len(raw) > 4<<20 || json.Unmarshal(raw, &req) != nil {
		return okEnvelope(pluginapi.StreamChunkInterceptResponse{})
	}
	r := currentQuotaRefresher()
	now := time.Now()
	if r != nil {
		now = r.now()
	}
	if r == nil || !r.state.Config().EnableUsageFeedback || req.RequestID == "" || len(req.RequestID) > 256 {
		return okEnvelope(pluginapi.StreamChunkInterceptResponse{})
	}
	id, index := metadataValue(req.Metadata, "selected_auth_id"), metadataValue(req.Metadata, "selected_auth_index")
	binding, ok := responseBinding(r, id, index)
	if !ok {
		return okEnvelope(pluginapi.StreamChunkInterceptResponse{})
	}
	responseQuotaStreams.Lock()
	stream := boundQuotaStream(req.RequestID, binding)
	if stream == nil || (req.ChunkIndex >= 0 && req.ChunkIndex <= stream.chunk) {
		responseQuotaStreams.Unlock()
		return okEnvelope(pluginapi.StreamChunkInterceptResponse{})
	}
	var observations []quotaObservation
	if quota, ok := responseHeaderQuota(req.ResponseHeaders, now); ok && req.ChunkIndex == pluginapi.StreamChunkHeaderInitIndex {
		stream.observation.Quota, stream.observation.ObservedAt = quota, now
		observations = append(observations, stream.observation)
	}
	if req.ChunkIndex >= 0 {
		if stream.chunk >= 0 && req.ChunkIndex != stream.chunk+1 {
			stream.buffer = nil
			stream.dropping = true
		}
		stream.chunk = req.ChunkIndex
		stream.absorb(req.Body, func(frame []byte) {
			if quota, ok := responseEventQuota(frame, now); ok {
				stream.observation.Quota, stream.observation.ObservedAt = quota, now
				observations = append(observations, stream.observation)
			}
		})
	}
	responseQuotaStreams.Unlock()
	for _, observation := range observations {
		r.offerQuotaObservation(observation)
	}
	return okEnvelope(pluginapi.StreamChunkInterceptResponse{})
}

func (s *quotaStream) absorb(chunk []byte, handle func([]byte)) {
	// 支持跨分片和 CRLF；超限帧丢弃至下一分隔符，不能把半截正文当新额度事件。
	for _, b := range chunk {
		if b == '\r' {
			continue
		}
		if s.dropping {
			if b == '\n' && len(s.buffer) == 1 && s.buffer[0] == '\n' {
				s.dropping = false
				s.buffer = nil
			} else {
				s.buffer = []byte{b}
			}
			continue
		}
		s.buffer = append(s.buffer, b)
		if len(s.buffer) > 64<<10 {
			s.buffer = nil
			s.dropping = true
			continue
		}
		if len(s.buffer) >= 2 && bytes.Equal(s.buffer[len(s.buffer)-2:], []byte("\n\n")) {
			handle(s.buffer[:len(s.buffer)-2])
			s.buffer = nil
		}
	}
}

func handleQuotaCompletion(raw []byte) ([]byte, error) {
	var completion pluginapi.RequestCompletion
	if len(raw) > 256<<10 || json.Unmarshal(raw, &completion) != nil {
		return okEnvelope(map[string]any{})
	}
	responseQuotaStreams.Lock()
	stream := responseQuotaStreams.items[completion.RequestID]
	delete(responseQuotaStreams.items, completion.RequestID)
	responseQuotaStreams.Unlock()
	if stream != nil && completion.Outcome == pluginapi.RequestCompletionSucceeded && completion.StatusCode >= 200 && completion.StatusCode < 300 && !stream.observation.ObservedAt.IsZero() {
		observation := stream.observation
		observation.Verified = !completion.StartedAt.IsZero() && !completion.StartedAt.After(observation.ObservedAt)
		if r := currentQuotaRefresher(); r != nil {
			r.offerQuotaObservation(observation)
		}
	}
	return okEnvelope(map[string]any{})
}

type responseQuotaWindow struct {
	Used    *float64 `json:"used_percent"`
	Minutes *float64 `json:"window_minutes"`
	Reset   *float64 `json:"reset_at"`
	After   *float64 `json:"reset_after_seconds"`
}

func responseEventQuota(frame []byte, now time.Time) (ParsedQuota, bool) {
	var data []byte
	eventName := ""
	for _, line := range bytes.Split(frame, []byte("\n")) {
		if bytes.HasPrefix(line, []byte("event:")) {
			eventName = strings.TrimSpace(string(line[6:]))
		}
		if bytes.HasPrefix(line, []byte("data:")) {
			data = append(data, bytes.TrimSpace(line[5:])...)
			data = append(data, '\n')
		}
	}
	var event struct {
		Type    string `json:"type"`
		LimitID string `json:"limit_id"`
		Plan    string `json:"plan_type"`
		Limits  *struct {
			Allowed   *bool                `json:"allowed"`
			Reached   *bool                `json:"limit_reached"`
			Primary   *responseQuotaWindow `json:"primary"`
			Secondary *responseQuotaWindow `json:"secondary"`
		} `json:"rate_limits"`
	}
	if json.Unmarshal(data, &event) != nil || (event.Type != "codex.rate_limits" && !(event.Type == "" && eventName == "codex.rate_limits")) || (event.LimitID != "" && event.LimitID != "codex") || event.Limits == nil {
		return ParsedQuota{}, false
	}
	q := ParsedQuota{PlanType: event.Plan}
	limited := (event.Limits.Allowed != nil && !*event.Limits.Allowed) || (event.Limits.Reached != nil && *event.Limits.Reached)
	primary := parseResponseWindow(event.Limits.Primary, limited, now)
	secondary := parseResponseWindow(event.Limits.Secondary, limited, now)
	if event.Limits.Primary != nil && primary == nil || event.Limits.Secondary != nil && secondary == nil {
		return ParsedQuota{}, false
	}
	return responseWindowsQuota(q, primary, secondary)

}

func validQuotaNumber(n *float64) bool { return n != nil && !math.IsNaN(*n) && !math.IsInf(*n, 0) }

func parseResponseWindow(w *responseQuotaWindow, limited bool, now time.Time) *QuotaWindow {
	if w == nil || !validQuotaNumber(w.Used) || *w.Used < 0 || *w.Used > 100 || !validQuotaNumber(w.Minutes) || *w.Minutes <= 0 || *w.Minutes > 100000 {
		return nil
	}
	seconds := int64(*w.Minutes * 60)
	reset := time.Time{}
	if w.Reset != nil {
		if !validQuotaNumber(w.Reset) || *w.Reset <= 0 || *w.Reset >= 4102444800 {
			return nil
		}
		reset = time.Unix(int64(*w.Reset), 0)
	} else if validQuotaNumber(w.After) && *w.After >= 0 && *w.After <= 100000*60 {
		reset = now.Add(time.Duration(*w.After * float64(time.Second)))
	}
	if reset.IsZero() {
		return nil
	}
	used := *w.Used
	return &QuotaWindow{UsedPercent: &used, LimitWindowSeconds: &seconds, ResetAt: reset, Exhausted: limited || used >= 100}
}

func responseWindowsQuota(q ParsedQuota, windows ...*QuotaWindow) (ParsedQuota, bool) {
	q.FiveHour, q.LongWindow = nil, nil
	for _, window := range windows {
		if window == nil {
			continue
		}
		if window.LimitWindowSeconds == nil {
			return ParsedQuota{}, false
		}
		w := *window
		switch seconds := *w.LimitWindowSeconds; {
		case seconds >= 299*60 && seconds <= 301*60:
			if q.FiveHour != nil {
				return ParsedQuota{}, false
			}
			w.Kind = WindowFiveHour
			q.FiveHour = &w
		case seconds >= 10079*60 && seconds <= 10081*60:
			if q.LongWindow != nil {
				return ParsedQuota{}, false
			}
			w.Kind = WindowWeekly
			q.LongWindow = &w
			q.Family = AccountFamilyWeekly
		case seconds >= 40319*60 && seconds <= 44641*60:
			if q.LongWindow != nil {
				return ParsedQuota{}, false
			}
			w.Kind = WindowMonthly
			q.LongWindow = &w
			q.Family = AccountFamilyMonthly
		default:
			return ParsedQuota{}, false
		}
	}
	return q, q.LongWindow != nil
}

func classifyResponseQuota(q ParsedQuota, now time.Time) (ParsedQuota, bool) {
	return responseWindowsQuota(q, q.FiveHour, q.LongWindow)
}

func responseHeaderQuota(headers http.Header, now time.Time) (ParsedQuota, bool) {
	normalized := make(map[string]string)
	for key, values := range headers {
		key = strings.ToLower(key)
		if !strings.HasPrefix(key, "x-codex-") {
			continue
		}
		if _, exists := normalized[key]; exists || len(values) != 1 {
			return ParsedQuota{}, false
		}
		normalized[key] = strings.TrimSpace(values[0])
	}
	get := func(key string) string { return normalized[key] }
	number := func(key string) *float64 {
		v, err := strconv.ParseFloat(get(key), 64)
		if err != nil {
			return nil
		}
		return &v
	}
	window := func(prefix string) *responseQuotaWindow {
		return &responseQuotaWindow{Used: number(prefix + "-used-percent"), Minutes: number(prefix + "-window-minutes"), Reset: number(prefix + "-reset-at"), After: number(prefix + "-reset-after-seconds")}
	}
	for key, value := range normalized {
		if strings.HasPrefix(key, "x-codex-primary-") || strings.HasPrefix(key, "x-codex-secondary-") {
			if strings.HasSuffix(key, "-used-percent") || strings.HasSuffix(key, "-window-minutes") || strings.HasSuffix(key, "-reset-at") || strings.HasSuffix(key, "-reset-after-seconds") {
				if value == "" || !validQuotaNumber(number(key)) {
					return ParsedQuota{}, false
				}
			}
		}
	}
	limited := get("x-codex-allowed") == "false" || get("x-codex-limit-reached") == "true"
	primary := parseResponseWindow(window("x-codex-primary"), limited, now)
	if (get("x-codex-primary-used-percent") != "" || get("x-codex-primary-window-minutes") != "" || get("x-codex-primary-reset-at") != "") && primary == nil {
		return ParsedQuota{}, false
	}
	secondary := parseResponseWindow(window("x-codex-secondary"), limited, now)
	if (get("x-codex-secondary-used-percent") != "" || get("x-codex-secondary-window-minutes") != "" || get("x-codex-secondary-reset-at") != "") && secondary == nil {
		return ParsedQuota{}, false
	}
	return responseWindowsQuota(ParsedQuota{PlanType: get("x-codex-plan-type")}, primary, secondary)
}

func (r *QuotaRefresher) offerQuotaObservation(o quotaObservation) {
	select {
	case r.quotaObservations <- o:
	default:
	}
}

func (r *QuotaRefresher) consumeQuotaObservations(stop <-chan struct{}) {
	for {
		select {
		case <-stop:
			return
		case o := <-r.quotaObservations:
			if err := r.acceptQuotaObservation(o); err != nil {
				r.state.RecordLog("warn", "quota.observation_pending", "额度观测尚未写入，等待后续有效证据", nil, r.now())
			}
		}
	}
}

func healthyQuota(q ParsedQuota, now time.Time) bool {
	if _, valid := classifyResponseQuota(q, now); !valid || q.UsageLimitReached {
		return false
	}
	for _, w := range []*QuotaWindow{q.FiveHour, q.LongWindow} {
		if w != nil && (!validQuotaNumber(w.UsedPercent) || *w.UsedPercent < 0 || *w.UsedPercent >= 100 || w.Exhausted || !w.ResetAt.After(now) || w.LimitWindowSeconds == nil || *w.LimitWindowSeconds <= 0 || w.ResetAt.After(now.Add(time.Duration(*w.LimitWindowSeconds)*time.Second+3*time.Minute))) {
			return false
		}
	}
	return true
}

func (r *QuotaRefresher) acceptQuotaObservation(o quotaObservation) error {
	return r.acceptQuotaObservationAt(o, r.now())
}

func (r *QuotaRefresher) acceptQuotaObservationAt(o quotaObservation, now time.Time) error {
	roster, _ := failClosedRosterAt(r.runtimeRoster(), now)
	if r.bindings == nil || !normalRosterBackgroundAllowed(roster) || o.StartedAt.IsZero() || o.StartedAt.After(o.ObservedAt) || o.ObservedAt.IsZero() || o.ObservedAt.After(now.Add(5*time.Second)) || now.Sub(o.ObservedAt) > 2*time.Minute {
		return nil
	}
	accepted := false
	queued := false
	var persistErr error
	write := WritebackVersion{Token: o.Binding.ExecutionToken(0), Login: o.Binding.Login, Fingerprint: o.Binding.Fingerprint}
	if !r.bindings.ApplyIfCurrent(o.Binding.AuthID, write, func() {
		r.state.mu.Lock()
		defer r.state.mu.Unlock()
		if !r.state.admissionCurrentLocked(o.Binding.AuthID, r.state.cpaAdmissionVersion) {
			return
		}
		key := "auth:" + o.Binding.AuthID
		a := r.state.accounts[key]
		if (a.AuthIndex != "" && a.AuthIndex != o.Binding.AuthIndex) || a.QuotaObservedAt.After(o.ObservedAt) || a.QuotaReadStartedAt.After(o.StartedAt) {
			return
		}
		if !a.QuotaFailureAt.IsZero() && !o.StartedAt.After(a.QuotaFailureAt) {
			return
		}
		if a.Refresh.AuthFailure {
			return
		}
		healthy := o.Verified && healthyQuota(o.Quota, now)
		needsRecovery := a.TemporaryExhausted || a.Quota.LongWindow == nil || o.Source == "probe"
		if healthy && needsRecovery {
			// 先持久化后解除本地临时阻断，崩溃不会丢失尚未提交给管理器的恢复。
			persistErr = r.queueQuotaRecovery(o)
			if persistErr != nil {
				return
			}
			queued = true
		}
		a.AuthID, a.AuthIndex, a.Provider = o.Binding.AuthID, o.Binding.AuthIndex, "codex"
		a.Priority = r.state.cpaAdmission.Priority
		a.Instance, a.AdmissionEpoch, a.TierGeneration = o.Binding.Instance, o.Binding.Admission, TierGeneration(o.Binding.Generation)
		a.BindingEpoch, a.TokenEpoch = o.Binding.Generation, o.Binding.Token
		a.LoginEpoch, a.CredentialFingerprint = o.Binding.Login, o.Binding.Fingerprint
		shifted := quotaWindowShifted(a, o.Quota)
		q := cloneParsedQuota(o.Quota)
		if o.Source == "response" {
			if q.PlanType == "" {
				q.PlanType = a.Quota.PlanType
			}
			q.CodeReviewWindows, q.AdditionalWindows = a.Quota.CodeReviewWindows, a.Quota.AdditionalWindows
			q.ResetCredits, q.ResetCreditsAvailableCount, q.ResetCreditsTotalEarnedCount = a.Quota.ResetCredits, a.Quota.ResetCreditsAvailableCount, a.Quota.ResetCreditsTotalEarnedCount
		}
		a.Quota, a.Family = q, q.Family
		a.QuotaReadStartedAt, a.QuotaObservedAt = o.StartedAt, o.ObservedAt
		a.LastSuccessAt, a.LastRefreshAt = o.ObservedAt, o.ObservedAt
		a.Stale = false
		if o.Verified {
			a.LastError = ""
			a.Refresh = AccountRefreshState{}
		}
		if healthy && (shifted || (o.Source == "response" && (a.FailureFiveResetAt.IsZero() || o.Quota.FiveHour != nil))) {
			a.TemporaryExhausted = false
			a.TemporaryResetAt = time.Time{}
		}
		r.state.accounts[key] = a
		accepted = true
	}) {
		return ErrStaleExecutionToken
	}
	if persistErr != nil {
		return persistErr
	}
	if !accepted {
		return nil
	}
	if queued {
		if _, err := r.recoveryConfiguration(); err != nil {
			r.state.RecordLog("warn", "quota.recovery_pending", "CPAMP 恢复配置不可用，待办已保留", map[string]any{"reason_code": err.Error()}, now)
		}
	}
	publishSchedulerState(r.state, highestTierSet(r.runtimeRoster()), now)
	if o.Verified && o.Source == "response" {
		if err := r.reconcileObservedProbeWindows(o.Binding.Instance, o.Quota); err != nil {
			return err
		}
	}
	r.wakeRefreshLoop()
	return nil
}

func (r *QuotaRefresher) applyProbeQuota(intent Intent, value probeReadResult) error {
	if r.bindings == nil {
		return nil
	}
	b, ok := r.bindings.Lookup(intent.AuthID)
	if !ok || !ValidateWriteback(BindingVersion{Instance: b.Instance, Admission: b.Admission, Tier: TierGeneration(b.Generation), Login: b.Login, Fingerprint: b.Fingerprint}, WritebackVersion{Token: intent.Token, Login: intent.Login, Fingerprint: intent.Fingerprint}) {
		return ErrStaleExecutionToken
	}
	// Probe 已在读完成时采样；写回沿同一时点，不能重新驱动其调度时钟。
	return r.acceptQuotaObservationAt(quotaObservation{Binding: b, Quota: value.Quota, StartedAt: value.StartedAt, ObservedAt: value.ObservedAt, Verified: value.Verified, Source: "probe"}, value.ObservedAt)
}
