package policy

// Effect represents the outcome of a rule evaluation.
type Effect string

const (
	// EffectAllow grants the action.
	EffectAllow Effect = "ALLOW"
	// EffectDeny blocks the action.
	EffectDeny Effect = "DENY"
)

// IsDeny returns true for the built-in deny effect.
// Deny effects short-circuit evaluation (first deny wins).
func (e Effect) IsDeny() bool {
	return e == EffectDeny
}
