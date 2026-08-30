package main

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// activationRequests returns every request the host saw for the activation
// endpoint, so a test can assert both what was sent and how many times.
func activationRequests(host *sequenceProbeHost) []pluginapi.HTTPRequest {
	host.mu.Lock()
	defer host.mu.Unlock()
	var sent []pluginapi.HTTPRequest
	for _, req := range host.requests {
		if req.URL == codexResetProbeEndpoint {
			sent = append(sent, req)
		}
	}
	return sent
}

// TestCodexActivationRequestUsesOfficialResponsesProtocol pins the wire shape of
// the activation request. The retired ".../responses/compact" path answered 404
// for every send, so the URL, the four Codex CLI headers and the
// stream/store/message body are the contract that has to stay put; a silent
// drift here reproduces the outage with no failing test.
func TestCodexActivationRequestUsesOfficialResponsesProtocol(t *testing.T) {
	request := codexResetProbeRequest(CodexCredentials{AccessToken: "access-token", ChatGPTAccountID: "acct-1"})

	if request.Method != http.MethodPost {
		t.Fatalf("Method = %q, want POST", request.Method)
	}
	if request.URL != "https://chatgpt.com/backend-api/codex/responses" {
		t.Fatalf("URL = %q, want the official Codex responses endpoint", request.URL)
	}
	if strings.HasSuffix(request.URL, "/compact") {
		t.Fatalf("URL = %q still targets the retired compact path", request.URL)
	}

	// Header names are compared by exact map key: the upstream client sends
	// "OpenAI-Beta" and "originator" in that casing, and http.Header.Get would
	// canonicalize them away instead of checking what really goes on the wire.
	wantHeaders := map[string][]string{
		"Accept":             {"text/event-stream"},
		"Authorization":      {"Bearer access-token"},
		"Chatgpt-Account-Id": {"acct-1"},
		"Content-Type":       {"application/json"},
		"OpenAI-Beta":        {"responses=v1"},
		"originator":         {"codex_cli_rs"},
		"User-Agent":         {codexResetProbeUserAgentHeader},
	}
	if got := map[string][]string(request.Headers); !reflect.DeepEqual(got, wantHeaders) {
		t.Fatalf("Headers = %#v, want %#v", got, wantHeaders)
	}

	var body struct {
		Model        string `json:"model"`
		Instructions string `json:"instructions"`
		Store        *bool  `json:"store"`
		Stream       *bool  `json:"stream"`
		Input        []struct {
			Type    string `json:"type"`
			Role    string `json:"role"`
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"input"`
		Messages any `json:"messages"`
	}
	if err := json.Unmarshal(request.Body, &body); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v; body=%s", err, request.Body)
	}
	if body.Model != codexResetProbeModel || body.Model == "" {
		t.Fatalf("model = %q, want %q", body.Model, codexResetProbeModel)
	}
	if body.Instructions == "" {
		t.Fatalf("instructions = %q, want a non-empty system prompt", body.Instructions)
	}
	if body.Store == nil || *body.Store {
		t.Fatalf("store = %v, want an explicit false", body.Store)
	}
	if body.Stream == nil || !*body.Stream {
		t.Fatalf("stream = %v, want an explicit true", body.Stream)
	}
	if body.Messages != nil {
		t.Fatalf("body carries a chat-style messages field: %s", request.Body)
	}
	if len(body.Input) != 1 || body.Input[0].Type != "message" || body.Input[0].Role != "user" {
		t.Fatalf("input = %#v, want one user message envelope", body.Input)
	}
	if parts := body.Input[0].Content; len(parts) != 1 || parts[0].Type != "input_text" || parts[0].Text == "" {
		t.Fatalf("input content = %#v, want one non-empty input_text part", parts)
	}
}

// TestCodexActivationRequestBodyIsIsolatedPerSend guards the shared encoding:
// the payload is marshalled once at init, so handing the same backing array to
// every send would let one host client corrupt all later activations.
func TestCodexActivationRequestBodyIsIsolatedPerSend(t *testing.T) {
	first := resetProbePayloadBytes()
	second := resetProbePayloadBytes()
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("payload is not stable: %s vs %s", first, second)
	}
	first[0] = 'X'
	if third := resetProbePayloadBytes(); !reflect.DeepEqual(second, third) {
		t.Fatalf("mutating one payload copy changed the next one: %s vs %s", second, third)
	}
}

// TestCodexActivationRequestOmitsUnknownAccountHeader keeps an empty account id
// out of the header set rather than sending "Chatgpt-Account-Id: ".
func TestCodexActivationRequestOmitsUnknownAccountHeader(t *testing.T) {
	request := codexResetProbeRequest(CodexCredentials{AccessToken: "access-token", ChatGPTAccountID: "  "})
	if values, ok := map[string][]string(request.Headers)["Chatgpt-Account-Id"]; ok {
		t.Fatalf("Chatgpt-Account-Id = %#v, want the header omitted when the id is unknown", values)
	}
}

// TestProbeActivationSendsOfficialProtocolAndVerifies is the success path end to
// end: one activation POST with the official protocol, then the verify read that
// confirms the window came alive. The sent and verified log entries must name the
// endpoint by its safe label and carry the real HTTP status.
func TestProbeActivationSendsOfficialProtocolAndVerifies(t *testing.T) {
	now := time.Date(2026, 8, 29, 3, 0, 0, 0, time.UTC)
	r, host, binding := newManualProbeRuntime(t, now, func(cfg *Config) {
		cfg.ProbeSendTimezone = "UTC"
		cfg.ProbeSendWindows = mustWindows(t, "02:00-04:00")
		cfg.ProbeTriggerMinutes = []int{7 * 60}
	})
	host.mu.Lock()
	host.probeBody = []byte("event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"status\":\"completed\"}}\n\ndata: [DONE]\n")
	host.mu.Unlock()
	var propagationDelay time.Duration
	r.coordinator.opts.PropagationWait = func(_ context.Context, delay time.Duration) error {
		propagationDelay = delay
		return nil
	}

	if _, err := r.RunManualProbePass(context.Background()); err != nil {
		t.Fatal(err)
	}
	if propagationDelay != probeActivationVerifyDelay {
		t.Fatalf("propagation delay = %s, want one %s wait", propagationDelay, probeActivationVerifyDelay)
	}

	sent := activationRequests(host)
	if len(sent) != 1 {
		t.Fatalf("activation POST count = %d, want exactly 1", len(sent))
	}
	if sent[0].Method != http.MethodPost || sent[0].URL != codexResetProbeEndpoint {
		t.Fatalf("activation request = %s %s, want POST %s", sent[0].Method, sent[0].URL, codexResetProbeEndpoint)
	}
	if !reflect.DeepEqual(sent[0].Body, resetProbePayloadBytes()) {
		t.Fatalf("activation body = %s, want the official responses payload", sent[0].Body)
	}
	headers := map[string][]string(sent[0].Headers)
	for key, want := range map[string]string{
		"OpenAI-Beta":        codexResetProbeBetaHeader,
		"originator":         codexResetProbeOriginatorHeader,
		"Accept":             codexResetProbeAcceptHeader,
		"Chatgpt-Account-Id": "acct",
	} {
		if got := headers[key]; len(got) != 1 || got[0] != want {
			t.Fatalf("header %q = %#v, want %q", key, got, want)
		}
	}

	window, ok := r.probeController.Window(binding.Instance, ProbeWindowFiveHour)
	if !ok || window.State != ProbeConfirmed {
		t.Fatalf("window = %#v, ok=%v, want Confirmed after a verified activation", window, ok)
	}
	for _, event := range []string{"probe.activation_sent", "probe.verified"} {
		fields := probeEventFields(t, r, r.now(), event)
		if fields["sent"] != true {
			t.Fatalf("%s sent = %#v, want true", event, fields["sent"])
		}
		if fields["activation_endpoint"] != codexResetProbeEndpointLabel {
			t.Fatalf("%s activation_endpoint = %#v, want %q", event, fields["activation_endpoint"], codexResetProbeEndpointLabel)
		}
		if fields["activation_http_status"] != http.StatusOK || fields["http_status"] != http.StatusOK {
			t.Fatalf("%s status fields = %#v", event, fields)
		}
	}
	assertNoProbeSecretsInLogs(t, r, now)
}

// TestProbeActivationHTTPFailureReportsSafeCodeStatusAndDoesNotResend covers the
// shape of the outage that motivated the protocol change: the send leaves, the
// upstream refuses it, and the failure has to be reported with an enumerated
// code plus the real status - once, without a blind retry inside the pass.
func TestProbeActivationHTTPFailureReportsSafeCodeStatusAndDoesNotResend(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
	}{
		{"retired endpoint", http.StatusNotFound},
		{"rate limited", http.StatusTooManyRequests},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Date(2026, 8, 29, 3, 0, 0, 0, time.UTC)
			r, host, binding := newManualProbeRuntime(t, now, func(cfg *Config) {
				cfg.ProbeSendTimezone = "UTC"
				cfg.ProbeSendWindows = mustWindows(t, "02:00-04:00")
				cfg.ProbeTriggerMinutes = []int{7 * 60}
			})
			host.mu.Lock()
			host.probeStatus = tc.status
			host.probeBody = []byte(`{"detail":"upstream-body-sentinel-770311"}`)
			host.mu.Unlock()

			result, err := r.RunManualProbePass(context.Background())
			if err == nil {
				t.Fatal("an upstream rejection must surface as an error, not a silent success")
			}
			if !result.Owned || !result.SendAllowed {
				t.Fatalf("result = %#v, want an owned pass that was allowed to send", result)
			}
			if sent := activationRequests(host); len(sent) != 1 {
				t.Fatalf("activation POST count = %d, want exactly 1 with no in-pass retry", len(sent))
			}
			fields := probeEventFields(t, r, r.now(), "probe.failed")
			if fields["error"] != "quota_http_status" || fields["error_category"] != "upstream_http" {
				t.Fatalf("probe.failed error fields = %#v", fields)
			}
			if fields["http_status"] != tc.status || fields["activation_http_status"] != tc.status {
				t.Fatalf("probe.failed status fields = %#v, want %d", fields, tc.status)
			}
			if fields["sent"] != true || fields["activation_endpoint"] != codexResetProbeEndpointLabel {
				t.Fatalf("probe.failed must name the endpoint the send really used: %#v", fields)
			}
			// A failed activation leaves the window unconfirmed so a later pass
			// can retry it under the gate, and never reports it as activated.
			if window, ok := r.probeController.Window(binding.Instance, ProbeWindowFiveHour); ok && window.State == ProbeConfirmed {
				t.Fatalf("window = %#v, want a failed activation to leave the window unconfirmed", window)
			}
			assertNoProbeSecretsInLogs(t, r, now)
			for _, entry := range r.state.Snapshot(now).Logs {
				for _, value := range entry.Fields {
					if text, ok := value.(string); ok && strings.Contains(text, "upstream-body-sentinel-770311") {
						t.Fatalf("probe log leaked the upstream body: %#v", entry)
					}
				}
			}
		})
	}
}

// TestProbeActivationRejectionInsideSuccessStatusIsNotHidden pins the other half
// of "no fallback hides a business failure": stream=true answers are SSE, so an
// upstream refusal arrives under HTTP 200. Trusting the status alone would
// record an activation that never happened.
func TestProbeActivationRejectionInsideSuccessStatusIsNotHidden(t *testing.T) {
	for _, tc := range []struct {
		name     string
		body     string
		wantCode string
	}{
		{
			name:     "sse response.failed",
			body:     "event: response.failed\ndata: {\"type\":\"response.failed\",\"response\":{\"id\":\"resp_1\",\"status\":\"failed\"}}\n",
			wantCode: probeActivationRejectedCode,
		},
		{
			name:     "sse usage limit",
			body:     "data: {\"type\":\"response.failed\",\"response\":{\"error\":{\"type\":\"usage_limit_reached\",\"message\":\"You have hit your usage limit\"}}}\n",
			wantCode: probeActivationUsageLimitCode,
		},
		{
			name:     "plain json error",
			body:     `{"error":{"type":"invalid_request_error","message":"model not found"}}`,
			wantCode: probeActivationRejectedCode,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Date(2026, 8, 29, 3, 0, 0, 0, time.UTC)
			r, host, binding := newManualProbeRuntime(t, now, func(cfg *Config) {
				cfg.ProbeSendTimezone = "UTC"
				cfg.ProbeSendWindows = mustWindows(t, "02:00-04:00")
				cfg.ProbeTriggerMinutes = []int{7 * 60}
			})
			host.mu.Lock()
			host.probeStatus = http.StatusOK
			host.probeBody = []byte(tc.body)
			host.mu.Unlock()

			if _, err := r.RunManualProbePass(context.Background()); err == nil {
				t.Fatal("a rejected activation under HTTP 200 must not be reported as success")
			}
			if sent := activationRequests(host); len(sent) != 1 {
				t.Fatalf("activation POST count = %d, want exactly 1", len(sent))
			}
			fields := probeEventFields(t, r, r.now(), "probe.failed")
			if fields["error"] != tc.wantCode || fields["error_category"] != "upstream_business" {
				t.Fatalf("probe.failed error fields = %#v, want %q/upstream_business", fields, tc.wantCode)
			}
			if fields["activation_http_status"] != http.StatusOK || fields["activation_endpoint"] != codexResetProbeEndpointLabel {
				t.Fatalf("probe.failed must report the 200 the rejection arrived under: %#v", fields)
			}
			if window, ok := r.probeController.Window(binding.Instance, ProbeWindowFiveHour); ok && window.State == ProbeConfirmed {
				t.Fatalf("window = %#v, want a rejected activation to leave the window unconfirmed", window)
			}
		})
	}
}

// TestCodexActivationRejectionReportsOnlyExplicitFailures keeps the body check
// one-sided. The verify quota read - not the response body - is what proves a
// window came alive, so an empty, truncated or merely unfamiliar body must not
// be turned into a failure the operator has to chase.
func TestCodexActivationRejectionReportsOnlyExplicitFailures(t *testing.T) {
	for _, body := range []string{
		"",
		"   ",
		`{"usage":{"total_tokens":1}}`,
		`{"error":null}`,
		"data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_1\"}}\n\ndata: [DONE]\n",
		"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"status\":\"completed\"}}\n",
		"not json at all",
	} {
		if code, rejected := codexActivationRejection([]byte(body)); rejected {
			t.Fatalf("codexActivationRejection(%q) = %q/true, want no rejection", body, code)
		}
	}
	for body, want := range map[string]string{
		`{"error":{"code":"model_not_found"}}`:                                      probeActivationRejectedCode,
		`{"error":"something went wrong"}`:                                          probeActivationRejectedCode,
		`{"response":{"error":{"message":"boom"}}}`:                                 probeActivationRejectedCode,
		`{"error":{"message":"You have hit your usage limit."}}`:                    probeActivationUsageLimitCode,
		"data: {\"type\":\"error\",\"error\":{\"code\":\"usage_limit_reached\"}}\n": probeActivationUsageLimitCode,
	} {
		code, rejected := codexActivationRejection([]byte(body))
		if !rejected || code != want {
			t.Fatalf("codexActivationRejection(%q) = %q/%v, want %q/true", body, code, rejected, want)
		}
	}
}

// TestProbeSentAttemptRecoveryVerifiesWithoutResending is the no-blind-resend
// boundary. An attempt whose activation already left the process is resumed by
// verifying the quota, never by sending a second quota-consuming request - the
// plugin cannot know whether the first send was billed, so a resend could spend
// the window it is trying to observe.
func TestProbeSentAttemptRecoveryVerifiesWithoutResending(t *testing.T) {
	now := time.Date(2026, 8, 29, 3, 0, 0, 0, time.UTC)
	active := []byte(`{"rate_limit":{"primary_window":{"used_percent":1,"limit_window_seconds":18000,"reset_at":"2026-08-29T08:00:00Z"}}}`)
	host := newProbeFixtureHost()
	host.quota = [][]byte{active, active, active, active}
	cfg := DefaultConfig()
	cfg.EnableResetProbe = true
	state := NewPluginState(cfg)
	state.ReplaceCPAAdmission(CPAAdmissionState{Observed: true, Priority: 9, AuthIDs: map[string]struct{}{"a": {}}})
	roster := HostRosterSnapshot{Capability: CapabilityA, Entries: []RosterEntry{{ID: "a", AuthIndex: "idx", Provider: "codex", Priority: intPtr(9)}}}
	path := filepath.Join(t.TempDir(), "state.json")
	adapter := &rosterCredentialHost{host: host, roster: roster}
	r, err := NewProductionQuotaRefresher(host, state, adapter, roster, path, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	adapter.bindings = r.bindings
	binding, _, err := r.BootstrapBinding(context.Background(), "a")
	if err != nil {
		t.Fatal(err)
	}
	// Persist exactly what a crash between "send" and "verify" leaves behind.
	if _, err = r.runtimeStore.Update(func(persisted *PersistentState) error {
		persisted.ReservedCeiling = 100
		persisted.ProbeWindows[binding.Instance] = map[ProbeWindowKind]ProbeWindow{
			ProbeWindowFiveHour: {State: ProbeSentUnknown, Baseline: ResetProbeBaseline(now.Add(-time.Hour), 80, 5*time.Hour)},
		}
		persisted.ProbeAttempts[binding.Instance] = ProbeAttempt{
			Instance:        binding.Instance,
			AttemptID:       "sent-1",
			Windows:         []ProbeWindowKind{ProbeWindowFiveHour},
			Phase:           ProbeAttemptSentUnknown,
			SendFenceSeq:    1,
			CreatedAt:       now.Add(-time.Hour),
			VerifyNotBefore: now.Add(-time.Hour),
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// Recovery is what a restart does, so run it through a restarted runtime.
	restartAdapter := &rosterCredentialHost{host: host, roster: roster}
	restart, err := NewProductionQuotaRefresher(host, state, restartAdapter, roster, path, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	restartAdapter.bindings = restart.bindings
	if err = restart.RunProbeRecoveryOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	if sent := activationRequests(host); len(sent) != 0 {
		t.Fatalf("recovery resent %d activation requests, want 0", len(sent))
	}
	fields := probeEventFields(t, restart, now, "probe.verified")
	if fields["recovery"] != true || fields["sent"] != true {
		t.Fatalf("probe.verified fields = %#v, want a recovered send", fields)
	}
	if fields["activation_endpoint"] != codexResetProbeEndpointLabel {
		t.Fatalf("probe.verified activation_endpoint = %#v, want %q", fields["activation_endpoint"], codexResetProbeEndpointLabel)
	}
	// The send happened in an earlier process, so no status was ever observed
	// here; reporting one would be a fabrication.
	if _, ok := fields["activation_http_status"]; ok {
		t.Fatalf("recovery must not invent a status for a send it never made: %#v", fields)
	}
	persisted, err := restart.runtimeStore.PersistentSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if attempt, ok := persisted.ProbeAttempts[binding.Instance]; ok {
		t.Fatalf("recovered attempt was not retired: %#v", attempt)
	}
}

// assertNoProbeSecretsInLogs fails if any probe log entry carries a credential,
// an Authorization header or the raw activation URL.
func assertNoProbeSecretsInLogs(t *testing.T, r *QuotaRefresher, now time.Time) {
	t.Helper()
	for _, entry := range r.state.Snapshot(now).Logs {
		rendered := strings.ToLower(entry.Message)
		for key, value := range entry.Fields {
			rendered += " " + strings.ToLower(key)
			if text, ok := value.(string); ok {
				rendered += " " + strings.ToLower(text)
			}
		}
		for _, forbidden := range []string{"access", "bearer", "authorization", "refresh_token", "id_token", "cookie", strings.ToLower(codexResetProbeEndpoint)} {
			if strings.Contains(rendered, forbidden) {
				t.Fatalf("probe log leaked %q: %#v", forbidden, entry)
			}
		}
	}
}
