package policy

import (
	"context"
	"errors"
)

// MatchedRule identifies a rule whose condition evaluated to true.
type MatchedRule struct {
	PolicyName  string
	RuleID      string
	Effect      Effect
	Description string
}

// Matches runs every rule and returns all matches in declaration order.
// Per-rule evaluation errors are aggregated into the returned error; the slice
// still contains all successful matches so callers can act on partial results.
// Does not mutate engine state — safe for concurrent calls.
func (e *Engine) Matches(ctx context.Context, input any) ([]MatchedRule, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	var matched []MatchedRule
	var errs []error

	for _, pol := range e.policies {
		for _, rule := range pol.rules {
			if err := ctx.Err(); err != nil {
				return matched, err
			}

			ok, err := rule.evaluate(input)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if ok {
				matched = append(matched, MatchedRule{
					PolicyName:  pol.policy.Name,
					RuleID:      rule.rule.ID,
					Effect:      rule.rule.Effect,
					Description: rule.rule.Description,
				})
			}
		}
	}

	if len(errs) > 0 {
		return matched, errors.Join(errs...)
	}
	return matched, nil
}
