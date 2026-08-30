package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

const (
	resetProbeAfterResetDelay = 10 * time.Minute
	resetProbeCloseThreshold  = 3 * time.Minute

	// codexResetProbeEndpoint is the ChatGPT Codex subscription responses
	// endpoint. The activation POST used to target ".../codex/responses/compact",
	// which upstream has retired: every send answered 404, so the probe logged
	// error=quota_http_status http_status=404 while the account's window stayed
	// lazy and was never actually activated.
	//
	// There is deliberately no fallback chain here. Trying a second endpoint
	// after a rejection would turn an upstream business failure into an
	// apparent success and hide exactly the breakage this constant just fixed.
	codexResetProbeEndpoint = "https://chatgpt.com/backend-api/codex/responses"
	// codexResetProbeEndpointLabel is the enumerated, credential-free name of
	// the endpoint above. Logs and management payloads quote this label so an
	// operator can tell which URL the activation really used; the raw URL is
	// redacted out of public strings (see redactPublicStatusString), so it can
	// never be the thing that answers that question.
	codexResetProbeEndpointLabel = "codex_responses"

	// Use the lowest-priced Codex model exposed by the installed catalog. The
	// CPA logs also show gpt-5.6-luna being accepted by the subscription
	// endpoint (quota/auth responses, not an unknown-model error), so it is a
	// valid and cheaper probe model than gpt-5.4-mini.
	codexResetProbeModel        = "gpt-5.6-luna"
	codexResetProbeInstructions = "You are a helpful assistant."
	codexResetProbePrompt       = "hi"

	// The subscription endpoint answers only requests shaped like the Codex
	// CLI's, so these header values are part of the protocol rather than
	// decoration. Non-canonical casing is intentional and matches the client
	// upstream expects; HTTP header names are case-insensitive on the wire.
	codexResetProbeAcceptHeader     = "text/event-stream"
	codexResetProbeBetaHeader       = "responses=v1"
	codexResetProbeOriginatorHeader = "codex_cli_rs"
	codexResetProbeUserAgentHeader  = "codex_cli_rs/0.76.0 (Debian 13.0.0; x86_64) WindowsTerminal"
)

// Enumerated failure codes for an activation the upstream accepted at the HTTP
// layer but rejected in the response body. They are fixed constants so a
// rejection can be reported without quoting any upstream text.
const (
	probeActivationRejectedCode   = "activation_rejected"
	probeActivationUsageLimitCode = "activation_usage_limit"
)

// codexResetProbeRequestBody is the Codex subscription activation payload.
// Upstream requires stream=true and store=false, and input must be a message
// list rather than a chat content string. The retired /compact path tolerated
// the shorter form; this one does not.
type codexResetProbeRequestBody struct {
	Model        string                        `json:"model"`
	Instructions string                        `json:"instructions"`
	Input        []codexResetProbeInputMessage `json:"input"`
	Store        bool                          `json:"store"`
	Stream       bool                          `json:"stream"`
}

type codexResetProbeInputMessage struct {
	Type    string                     `json:"type"`
	Role    string                     `json:"role"`
	Content []codexResetProbeInputPart `json:"content"`
}

type codexResetProbeInputPart struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// resetProbePayload is encoded once at init: the payload is a fixed literal, so
// re-marshalling per send could only ever reproduce the same bytes.
var resetProbePayload = mustEncodeResetProbePayload()

func mustEncodeResetProbePayload() []byte {
	encoded, err := json.Marshal(codexResetProbeRequestBody{
		Model:        codexResetProbeModel,
		Instructions: codexResetProbeInstructions,
		Input: []codexResetProbeInputMessage{{
			Type: "message",
			Role: "user",
			Content: []codexResetProbeInputPart{{
				Type: "input_text",
				Text: codexResetProbePrompt,
			}},
		}},
		Store:  false,
		Stream: true,
	})
	if err != nil {
		// Unreachable: the value is a fixed struct of strings and bools.
		panic("encode codex activation payload: " + err.Error())
	}
	return encoded
}

// codexResetProbeHeaders builds the activation request headers. The bearer
// token and the account id exist only inside the returned header set, which
// goes straight to the host client; no caller logs a header.
func codexResetProbeHeaders(credentials CodexCredentials) http.Header {
	headers := http.Header{
		"Accept":        []string{codexResetProbeAcceptHeader},
		"Authorization": []string{"Bearer " + credentials.AccessToken},
		"Content-Type":  []string{"application/json"},
		"OpenAI-Beta":   []string{codexResetProbeBetaHeader},
		"originator":    []string{codexResetProbeOriginatorHeader},
		"User-Agent":    []string{codexResetProbeUserAgentHeader},
	}
	if accountID := strings.TrimSpace(credentials.ChatGPTAccountID); accountID != "" {
		headers["Chatgpt-Account-Id"] = []string{accountID}
	}
	return headers
}

// codexResetProbeRequest is the single place the activation request is built,
// so the URL, headers and body that the WAL records as "sent" cannot drift from
// the ones that actually leave the process.
func codexResetProbeRequest(credentials CodexCredentials) pluginapi.HTTPRequest {
	return pluginapi.HTTPRequest{
		Method:  http.MethodPost,
		URL:     codexResetProbeEndpoint,
		Headers: codexResetProbeHeaders(credentials),
		Body:    resetProbePayloadBytes(),
	}
}

func probeWindowDuration(window QuotaWindow) (time.Duration, bool) {
	if window.LimitWindowSeconds != nil && *window.LimitWindowSeconds > 0 {
		return time.Duration(*window.LimitWindowSeconds) * time.Second, true
	}
	switch window.Kind {
	case WindowFiveHour:
		return 5 * time.Hour, true
	case WindowWeekly:
		return 7 * 24 * time.Hour, true
	default:
		return 0, false
	}
}

func firstObservationLazyWindow(now time.Time, window QuotaWindow) (time.Duration, bool) {
	if window.UsedPercent == nil || *window.UsedPercent != 0 || window.ResetAt.IsZero() {
		return 0, false
	}
	duration, ok := probeWindowDuration(window)
	if !ok || duration <= 0 {
		return 0, false
	}
	return duration, absDuration(window.ResetAt.Sub(now.Add(duration))) <= resetProbeCloseThreshold
}

func scheduleResetProbesFromPrevious(previous AccountState, current map[WindowKind]ResetProbeState, now time.Time) map[WindowKind]ResetProbeState {
	next := cloneResetProbes(current)
	for _, window := range resetProbeCandidateWindows(previous.Quota) {
		duration, ok := probeWindowDuration(window)
		if !ok || duration <= 0 || window.ResetAt.IsZero() || window.ResetAt.After(now) {
			continue
		}
		if existing, ok := next[window.Kind]; ok && existing.ResetAt.Equal(window.ResetAt) {
			continue
		}
		if next == nil {
			next = make(map[WindowKind]ResetProbeState)
		}
		next[window.Kind] = ResetProbeState{
			WindowKind:    window.Kind,
			WindowSeconds: int64(duration / time.Second),
			ResetAt:       window.ResetAt,
			NextCheckAt:   window.ResetAt.Add(resetProbeAfterResetDelay),
			Status:        ResetProbeStatusPending,
		}
	}
	return next
}

func resetProbeCandidateWindows(quota ParsedQuota) []QuotaWindow {
	windows := make([]QuotaWindow, 0, 2)
	if quota.FiveHour != nil {
		windows = append(windows, *quota.FiveHour)
	}
	if quota.LongWindow != nil {
		windows = append(windows, *quota.LongWindow)
	}
	return windows
}

func resetProbeDue(probe ResetProbeState, now time.Time) bool {
	return probe.Status == ResetProbeStatusPending && !probe.NextCheckAt.IsZero() && !probe.NextCheckAt.After(now)
}

func resetProbeDueAny(probes map[WindowKind]ResetProbeState, now time.Time) bool {
	for _, probe := range probes {
		if resetProbeDue(probe, now) {
			return true
		}
	}
	return false
}

func matchingProbeWindow(quota ParsedQuota, probe ResetProbeState) (QuotaWindow, bool) {
	for _, window := range resetProbeCandidateWindows(quota) {
		if probe.WindowKind != "" && window.Kind != probe.WindowKind {
			continue
		}
		return window, true
	}
	return QuotaWindow{}, false
}

func markResetProbeConfirmedActive(probe ResetProbeState) ResetProbeState {
	probe.Status = ResetProbeStatusConfirmedActive
	probe.Error = ""
	return probe
}

func markResetProbeVerified(probe ResetProbeState, now time.Time) ResetProbeState {
	probe.Status = ResetProbeStatusVerified
	probe.LastProbeAt = now
	probe.VerifiedAt = now
	probe.Error = ""
	return probe
}

func markResetProbeRetry(probe ResetProbeState, now time.Time, err error, credentials CodexCredentials, cfg Config) ResetProbeState {
	probe.LastProbeAt = now
	probe.Attempts++
	probe.Error = ""
	if err != nil {
		probe.Error = redactWithCredentials(err.Error(), credentials)
	}
	retryDelays := NormalizeConfig(cfg).RefreshRetryDelays
	if len(retryDelays) == 0 || probe.Attempts > len(retryDelays) {
		probe.Status = ResetProbeStatusFailed
		probe.NextCheckAt = time.Time{}
		return probe
	}
	probe.Status = ResetProbeStatusPending
	probe.NextCheckAt = now.Add(retryDelays[probe.Attempts-1])
	return probe
}

func looksLikeLazyReset(now time.Time, window QuotaWindow, windowSeconds int64) bool {
	if windowSeconds <= 0 || window.ResetAt.IsZero() {
		return false
	}
	duration := time.Duration(windowSeconds) * time.Second
	return absDuration(window.ResetAt.Sub(now.Add(duration))) <= resetProbeCloseThreshold
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

func resetProbeUsageEvidence(body []byte) bool {
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return false
	}
	for _, path := range [][]string{
		{"usage", "total_tokens"},
		{"usage", "prompt_tokens"},
		{"usage", "input_tokens"},
		{"usage", "completion_tokens"},
		{"usage", "output_tokens"},
		{"response", "usage", "total_tokens"},
		{"response", "usage", "prompt_tokens"},
		{"response", "usage", "input_tokens"},
		{"response", "usage", "completion_tokens"},
		{"response", "usage", "output_tokens"},
	} {
		if jsonNumberPathPositive(doc, path...) {
			return true
		}
	}
	return false
}

func jsonNumberPathPositive(root any, path ...string) bool {
	current := root
	for _, key := range path {
		obj, ok := current.(map[string]any)
		if !ok {
			return false
		}
		current, ok = obj[key]
		if !ok {
			return false
		}
	}
	value, ok := current.(float64)
	return ok && value > 0
}

// resetProbePayloadBytes returns a fresh copy of the activation payload so a
// caller (or a host client) that retains or rewrites the slice cannot corrupt
// the shared encoding for every later send.
func resetProbePayloadBytes() []byte {
	return append([]byte(nil), resetProbePayload...)
}

// probeActivationError reports an activation the upstream accepted at the HTTP
// layer and then rejected in the response body. Only the enumerated Code and
// the HTTP status are retained; the body that produced them is dropped here so
// it cannot reach a log entry or a management response.
type probeActivationError struct {
	Code   string
	Status int
}

func (e probeActivationError) Error() string {
	return "codex activation rejected by upstream: " + e.Code
}

// codexActivationRejection reports an explicit upstream business failure
// carried inside a 2xx activation response.
//
// stream=true answers are SSE, so a refused generation arrives as a
// response.failed/error event under HTTP 200. Treating "2xx" as success on its
// own would record an activation that never happened and leave the window lazy
// with no explanation.
//
// The check is deliberately one-sided: it reports only explicit evidence of
// failure. An empty, truncated or otherwise opaque body is not evidence that
// the activation failed, and the quota re-read in the verify step - not this
// function - is what confirms that a window really came alive.
func codexActivationRejection(body []byte) (string, bool) {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return "", false
	}
	if strings.Contains(trimmed, "data:") || strings.Contains(trimmed, "event:") {
		return codexActivationSSERejection(trimmed)
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(body, &root); err != nil {
		return "", false
	}
	if code, rejected := codexActivationErrorCode(root); rejected {
		return code, true
	}
	if nested, ok := codexActivationNested(root, "response"); ok {
		return codexActivationErrorCode(nested)
	}
	return "", false
}

func codexActivationSSERejection(stream string) (string, bool) {
	for _, line := range strings.Split(stream, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" || payload == "[DONE]" {
			continue
		}
		var event map[string]json.RawMessage
		if err := json.Unmarshal([]byte(payload), &event); err != nil {
			continue
		}
		if code, rejected := codexActivationErrorCode(event); rejected {
			return code, true
		}
		nested, hasNested := codexActivationNested(event, "response")
		if hasNested {
			if code, rejected := codexActivationErrorCode(nested); rejected {
				return code, true
			}
		}
		var eventType string
		if raw, ok := event["type"]; ok {
			_ = json.Unmarshal(raw, &eventType)
		}
		if eventType == "response.failed" || eventType == "error" {
			return probeActivationRejectedCode, true
		}
	}
	return "", false
}

func codexActivationNested(root map[string]json.RawMessage, key string) (map[string]json.RawMessage, bool) {
	raw, ok := root[key]
	if !ok {
		return nil, false
	}
	var nested map[string]json.RawMessage
	if err := json.Unmarshal(raw, &nested); err != nil {
		return nil, false
	}
	return nested, true
}

// codexActivationErrorCode maps an "error" member onto an enumerated code. The
// upstream message is only pattern-matched for the usage-limit case and is
// never returned, so no upstream text escapes.
func codexActivationErrorCode(root map[string]json.RawMessage) (string, bool) {
	raw, ok := root["error"]
	if !ok || string(raw) == "null" {
		return "", false
	}
	var payload struct {
		Type    string `json:"type"`
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		// error may also be a bare string; either shape still means rejected.
		return probeActivationRejectedCode, true
	}
	for _, text := range []string{payload.Type, payload.Code, payload.Message} {
		lowered := strings.ToLower(strings.TrimSpace(text))
		if strings.Contains(lowered, "usage_limit") || strings.Contains(lowered, "usage limit") {
			return probeActivationUsageLimitCode, true
		}
	}
	return probeActivationRejectedCode, true
}
