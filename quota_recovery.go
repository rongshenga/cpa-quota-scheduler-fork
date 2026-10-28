package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// 恢复队列只保存账号绑定和已脱敏额度；未知提交通过原冷却记录核对，不直接写 CPA 开关。
type quotaRecovery struct {
	Observation quotaObservation `json:"observation"`
	NextAt      time.Time        `json:"next_at"`
	Attempts    int              `json:"attempts"`
}

type recoveryConfig struct {
	URL string `json:"url"`
	Key string `json:"key"`
}
type cooldownRecord struct {
	AuthFileName string `json:"authFileName"`
	AuthIndex    string `json:"authIndex"`
	Provider     string `json:"provider"`
	Owner        string `json:"owner"`
	Reason       string `json:"reasonCode"`
	Window       string `json:"windowKind"`
	RecoverAt    int64  `json:"recoverAtMs"`
	DisabledAt   int64  `json:"disabledAtMs"`
	UpdatedAt    int64  `json:"updatedAtMs"`
}
type recoveryWindow struct {
	Used    float64 `json:"usedPercent"`
	Seconds int64   `json:"windowSeconds"`
	ResetAt int64   `json:"resetAtMs"`
}
type verifiedRecoveryRequest struct {
	AuthFileName       string           `json:"authFileName"`
	AuthIndex          string           `json:"authIndex"`
	Provider           string           `json:"provider"`
	ExpectedDisabledAt int64            `json:"expectedDisabledAtMs"`
	ExpectedRecoverAt  int64            `json:"expectedRecoverAtMs"`
	ExpectedUpdatedAt  int64            `json:"expectedUpdatedAtMs"`
	ObservedAt         int64            `json:"observedAtMs"`
	StartedAt          int64            `json:"startedAtMs"`
	Source             string           `json:"source"`
	Windows            []recoveryWindow `json:"windows"`
}

func (r *QuotaRefresher) recoveryConfiguration() (recoveryConfig, error) {
	if r.runtimeStore == nil {
		return recoveryConfig{}, errors.New("recovery_not_configured")
	}
	path := filepath.Join(filepath.Dir(r.runtimeStore.path), "cpamp-recovery.json")
	info, err := os.Lstat(path)
	if err != nil {
		return recoveryConfig{}, errors.New("recovery_not_configured")
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 8192 {
		return recoveryConfig{}, errors.New("recovery_config_unsafe")
	}
	f, err := os.Open(path)
	if err != nil {
		return recoveryConfig{}, errors.New("recovery_config_unavailable")
	}
	defer f.Close()
	actual, err := f.Stat()
	if err != nil || !os.SameFile(info, actual) {
		return recoveryConfig{}, errors.New("recovery_config_changed")
	}
	var cfg recoveryConfig
	decoder := json.NewDecoder(io.LimitReader(f, 8193))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&cfg) != nil || decoder.Decode(new(any)) != io.EOF {
		return cfg, errors.New("recovery_config_invalid")
	}
	u, err := url.Parse(cfg.URL)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return cfg, errors.New("recovery_origin_invalid")
	}
	local := net.ParseIP(u.Hostname())
	loopback := local != nil && local.IsLoopback()
	if u.Scheme != "https" && !(u.Scheme == "http" && loopback) {
		return cfg, errors.New("recovery_https_required")
	}
	if cfg.Key == "" || len(cfg.Key) > 4096 || strings.ContainsAny(cfg.Key, " \t\r\n") {
		return cfg, errors.New("recovery_key_invalid")
	}
	cfg.URL = strings.TrimRight(cfg.URL, "/")
	return cfg, nil
}

func recoveryHTTP(ctx context.Context, cfg recoveryConfig, path string, body any, out any) error {
	if (path != "/usage-service/quota-cooldowns" || body != nil) && (path != "/usage-service/quota-cooldowns/recover-verified" || body == nil) {
		return errors.New("recovery_request_invalid")
	}
	var data []byte
	var err error
	method := http.MethodGet
	if body != nil {
		data, err = json.Marshal(body)
		if err != nil {
			return errors.New("recovery_request_invalid")
		}
		method = http.MethodPost
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, cfg.URL+path, bytes.NewReader(data))
	if err != nil {
		return errors.New("recovery_request_invalid")
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Key)
	req.Header.Set("Content-Type", "application/json")
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 8 * time.Second, MaxResponseHeaderBytes: 32768}
	defer transport.CloseIdleConnections()
	client := http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect_refused") }}
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("recovery_transport_unknown")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New("recovery_manager_rejected")
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20+1))
	if err != nil || len(raw) > 1<<20 || json.Unmarshal(raw, out) != nil {
		return errors.New("recovery_response_unknown")
	}
	return nil
}

func (r *QuotaRefresher) queueQuotaRecovery(o quotaObservation) error {

	if r.runtimeStore == nil {
		return nil
	}
	_, err := r.runtimeStore.Update(func(s *PersistentState) error {
		if s.QuotaRecoveries == nil {
			s.QuotaRecoveries = map[string]quotaRecovery{}
		}
		if len(s.QuotaRecoveries) >= 128 {
			if _, ok := s.QuotaRecoveries[o.Binding.AuthID]; !ok {
				return errors.New("recovery_queue_full")
			}
		}
		old, ok := s.QuotaRecoveries[o.Binding.AuthID]
		if ok && !o.ObservedAt.After(old.Observation.ObservedAt) {
			return nil
		}
		next := quotaRecovery{Observation: o, NextAt: r.now()}
		if ok && old.Observation.Binding == o.Binding {
			next.Attempts = old.Attempts
			if old.NextAt.After(next.NextAt) {
				next.NextAt = old.NextAt
			}
		}
		s.QuotaRecoveries[o.Binding.AuthID] = next
		return nil
	})
	return err
}

func (r *QuotaRefresher) quotaRecoveryDeadline() time.Time {
	if _, err := r.recoveryConfiguration(); err != nil {
		return time.Time{}
	}
	if r.runtimeStore == nil || !r.normalBackgroundAllowed() {
		return time.Time{}
	}
	r.recoveryMu.Lock()
	busy := r.recoveryRunning
	retryAt := r.recoveryRetryAt
	r.recoveryMu.Unlock()
	if busy {
		return time.Time{}
	}
	s, err := r.runtimeStore.PersistentSnapshot()
	if err != nil {
		return time.Time{}
	}
	var next time.Time
	for _, job := range s.QuotaRecoveries {
		if next.IsZero() || job.NextAt.Before(next) {
			next = job.NextAt
		}
	}
	if !next.IsZero() && retryAt.After(next) {
		next = retryAt
	}
	return next
}

func (r *QuotaRefresher) recoverQuotaSoon() {
	if _, err := r.recoveryConfiguration(); err != nil {
		return
	}
	if r.bindings == nil || r.runtimeStore == nil || !r.normalBackgroundAllowed() {
		return
	}
	r.mu.Lock()
	if r.stopping {
		r.mu.Unlock()
		return
	}
	r.recoveryMu.Lock()
	if r.recoveryRunning || r.recoveryRetryAt.After(r.now()) {
		r.recoveryMu.Unlock()
		r.mu.Unlock()
		return
	}
	r.recoveryRunning = true
	r.recoveryMu.Unlock()
	r.wg.Add(1)
	r.mu.Unlock()
	go func() {
		defer r.wg.Done()
		defer func() { r.recoveryMu.Lock(); r.recoveryRunning = false; r.recoveryMu.Unlock(); r.wakeRefreshLoop() }()
		s, err := r.runtimeStore.PersistentSnapshot()
		if err != nil {
			return
		}
		for id, job := range s.QuotaRecoveries {
			if job.NextAt.After(r.now()) {
				continue
			}
			r.mu.Lock()
			stopping := r.stopping
			r.mu.Unlock()
			if stopping {
				return
			}
			b, ok := r.bindings.Lookup(id)
			if !ok || b != job.Observation.Binding || !r.state.IsAuthAdmitted(id) {
				r.finishQuotaRecovery(id, job, true, nil)
				continue
			}
			intent := Intent{AuthID: id, Instance: b.Instance, Generation: TierGeneration(b.Generation), Class: OperationQuotaRecovery, Source: SourceProbeVerify, Token: b.ExecutionToken(0), Login: b.Login, Fingerprint: b.Fingerprint, Payload: job}
			result := r.coordinator.Submit(intent).Await(context.Background())
			done, _ := result.Value.(bool)
			r.finishQuotaRecovery(id, job, done && result.Err == nil, result.Err)
		}
	}()
}

func (r *QuotaRefresher) finishQuotaRecovery(id string, job quotaRecovery, done bool, err error) {
	_, writeErr := r.runtimeStore.Update(func(s *PersistentState) error {
		current, ok := s.QuotaRecoveries[id]
		if !ok || !current.Observation.ObservedAt.Equal(job.Observation.ObservedAt) {
			return nil
		}
		if done {
			delete(s.QuotaRecoveries, id)
		} else {
			current.Attempts++
			delay := time.Minute
			if current.Attempts > 3 {
				delay = 15 * time.Minute
			}
			current.NextAt = r.now().Add(delay)
			s.QuotaRecoveries[id] = current
		}
		return nil
	})
	if writeErr != nil {
		r.recoveryMu.Lock()
		r.recoveryRetryAt = r.now().Add(time.Minute)
		r.recoveryMu.Unlock()
	}
	if err != nil || writeErr != nil {
		reason := "recovery_pending"
		if writeErr != nil {
			reason = "recovery_state_unavailable"
		} else {
			switch err.Error() {
			case "recovery_not_configured", "recovery_config_unsafe", "recovery_config_invalid", "recovery_origin_invalid", "recovery_https_required", "recovery_key_invalid", "recovery_manager_rejected", "recovery_transport_unknown", "recovery_response_unknown", "recovery_identity_changed", "recovery_identity_ambiguous", "recovery_quota_not_ready", "recovery_evidence_older_than_disable", "recovery_newer_failure", "recovery_quota_unavailable":
				reason = err.Error()
			}
		}
		r.state.RecordLog("warn", "quota.recovery_pending", "额度恢复尚未完成，将核对原冷却记录后重试", map[string]any{"reason_code": reason}, r.now())
	}
}

func (r *QuotaRefresher) runQuotaRecovery(ctx context.Context, intent Intent, held *HeldLease) OperationResult {
	result := OperationResult{Token: intent.Token, Login: intent.Login, Fingerprint: intent.Fingerprint}
	job, ok := intent.Payload.(quotaRecovery)
	if !ok {
		result.Err = errors.New("recovery_payload_invalid")
		return result
	}
	cfg, err := r.recoveryConfiguration()
	if err != nil {
		result.Err = err
		return result
	}
	b := job.Observation.Binding
	var reply struct {
		Items *[]cooldownRecord `json:"items"`
	}
	err = held.DoHTTP(ctx, func(context.Context) error {
		return recoveryHTTP(ctx, cfg, "/usage-service/quota-cooldowns", nil, &reply)
	})
	if err != nil {
		result.Err = err
		return result
	}
	if reply.Items == nil {
		result.Err = errors.New("recovery_response_unknown")
		return result
	}
	var matched *cooldownRecord
	for i := range *reply.Items {
		c := &(*reply.Items)[i]
		if c.AuthIndex == b.AuthIndex && c.AuthFileName == b.AuthName && c.Provider == "codex" && c.Owner == "cpamp_usage_429" && c.Reason == "codex_usage_limit_reached" {
			if matched != nil {
				result.Err = errors.New("recovery_identity_ambiguous")
				return result
			}
			matched = c
		}
	}
	if matched == nil {
		result.Value = true
		return result
	}
	// 每次都核对当前凭据；未知提交先查原记录，过期证据只读重取，不补发激活。
	var authJSON []byte
	err = held.DoHTTP(ctx, func(context.Context) error { a, e := r.host.GetAuth(b.AuthIndex); authJSON = a.JSON; return e })
	if err != nil {
		result.Err = errors.New("recovery_auth_unavailable")
		return result
	}
	credentials, e := ExtractCodexCredentials(authJSON)
	if e != nil || credentials.ChatGPTAccountID == "" || NewCredentialFingerprint(credentials.ChatGPTAccountID, credentials.RefreshToken, b.AuthIndex) != b.Fingerprint {
		result.Err = errors.New("recovery_identity_changed")
		return result
	}
	o := job.Observation
	if r.now().Sub(o.ObservedAt) > time.Minute || job.Attempts > 0 {
		o.StartedAt = r.now()
		o.Quota, err = r.typedFetchQuota(ctx, held, credentials)
		o.ObservedAt = r.now()
		o.Source = "probe"
		o.Verified = true
		if err != nil {
			result.Err = errors.New("recovery_quota_unavailable")
			return result
		}
	}
	if !o.Verified || !healthyQuota(o.Quota, r.now()) {
		result.Err = errors.New("recovery_quota_not_ready")
		return result
	}
	if matched.UpdatedAt == 0 || o.StartedAt.UnixMilli() <= matched.DisabledAt {
		result.Err = errors.New("recovery_evidence_older_than_disable")
		return result
	}
	request := verifiedRecoveryRequest{AuthFileName: b.AuthName, AuthIndex: b.AuthIndex, Provider: "codex", ExpectedDisabledAt: matched.DisabledAt, ExpectedRecoverAt: matched.RecoverAt, ExpectedUpdatedAt: matched.UpdatedAt, ObservedAt: o.ObservedAt.UnixMilli(), StartedAt: o.StartedAt.UnixMilli(), Source: o.Source}
	for _, w := range []*QuotaWindow{o.Quota.FiveHour, o.Quota.LongWindow} {
		if w != nil {
			request.Windows = append(request.Windows, recoveryWindow{Used: *w.UsedPercent, Seconds: *w.LimitWindowSeconds, ResetAt: w.ResetAt.UnixMilli()})
		}
	}
	var recovered struct {
		Recovered bool `json:"recovered"`
	}
	err = held.DoHTTP(ctx, func(context.Context) error {
		current, ok := r.bindings.Lookup(b.AuthID)
		if !ok || current != b || !r.normalBackgroundAllowed() || !r.state.IsAuthAdmitted(b.AuthID) {
			return ErrStaleExecutionToken
		}
		r.state.mu.RLock()
		lastFailure := r.state.accounts["auth:"+b.AuthID].QuotaFailureAt
		r.state.mu.RUnlock()
		if !lastFailure.IsZero() && !o.StartedAt.After(lastFailure) {
			return errors.New("recovery_newer_failure")
		}
		return recoveryHTTP(ctx, cfg, "/usage-service/quota-cooldowns/recover-verified", request, &recovered)
	})
	if err != nil {
		result.Err = err
		return result
	}
	if !recovered.Recovered {
		result.Err = errors.New("recovery_not_confirmed")
		return result
	}
	result.Value = true
	r.state.RecordLog("info", "quota.reenabled", "已核对新额度并解除 CPAMP 额度禁用", nil, r.now())
	return result
}
