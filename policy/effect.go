package policy

// Effect represents the outcome of a rule evaluation.
type Effect string

const (
	// EffectAllow grants the action.
	EffectAllow Effect = "ALLOW"
	// EffectDeny blocks the action.
	EffectDeny Effect = "DENY"
)

// IsValid returns true when the effect is one of the supported values.
func (e Effect) IsValid() bool {
	switch e {
	case EffectAllow, EffectDeny:
		return true
	default:
		return false
	}
}
