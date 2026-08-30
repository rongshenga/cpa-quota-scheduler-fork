package main

// CPA invokes scheduler.pick for every request it routes, including requests
// for providers this plugin does not own. Recording each decision fills the
// bounded log ring — 200 entries by default — within minutes of normal Codex
// use, evicting the reset-probe and quota history the status page exists to
// show. That is how an activation failing with 404 on every attempt stayed
// unnoticed: the evidence was written, then immediately scrolled away.
//
// The ring therefore keeps only Codex-scoped scheduling faults, and only when
// the fault changes. Successful routing is not a fault, a non-Codex request is
// not this plugin's business, and a fault repeating on every request is one
// fault, not a thousand.

// schedulerDecisionReason values that describe a Codex-scoped fault worth one
// ring-buffer entry. Everything absent from this set is either routine routing
// or another provider's traffic.
var loggableSchedulerReasons = map[string]struct{}{
	"no_codex_candidates":   {},
	"no_selectable_account": {},
}

// schedulerDecisionLoggable reports whether a pick decision earns a log entry.
//
// verbose restores the pre-filter behaviour for debugging a routing problem;
// it is off by default because it is exactly the flood described above.
func schedulerDecisionLoggable(decision PickDecision, verbose bool) bool {
	if verbose {
		return true
	}
	// A selected account, or a delegation to a built-in scheduler, is the
	// plugin working as intended.
	if decision.AuthID != "" || decision.DelegateBuiltin != "" {
		return false
	}
	_, ok := loggableSchedulerReasons[decision.Reason]
	return ok
}

// schedulerDecisionDedupKey identifies a fault for consecutive-repeat
// suppression. Reason alone is the identity: the same shortage repeating
// across requests is one condition, and the model or provider that happened to
// hit it does not change what the operator has to fix.
func schedulerDecisionDedupKey(decision PickDecision) string {
	return decision.Reason
}
