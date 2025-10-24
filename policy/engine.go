package policy

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
)

// Engine evaluates compiled policies against an input context.
type Engine struct {
	defaultEffect Effect
	policies      []*compiledPolicy
}

// EngineOption configures compilation behaviour.
type EngineOption func(*engineConfig)

type engineConfig struct {
	exprOptions   []expr.Option
	defaultEffect Effect
	env           any
	strictTypes   bool
}

// WithExprOptions passes expr compilation options for every rule.
func WithExprOptions(opts ...expr.Option) EngineOption {
	return func(cfg *engineConfig) {
		cfg.exprOptions = append(cfg.exprOptions, opts...)
	}
}

// WithSchemaDefinition defines the expected data structure for type validation at compile time.
// Pass an empty struct to define which fields exist and their types.
// Unknown fields or type mismatches will be caught during policy compilation.
// Example: policy.WithSchemaDefinition(TransactionContext{})
func WithSchemaDefinition(schema any) EngineOption {
	return func(cfg *engineConfig) {
		cfg.env = schema
		cfg.strictTypes = true // Enable strict type checking when schema is provided
	}
}

// WithDefaultEffect defines the fallback effect used when no rule matches.
func WithDefaultEffect(effect Effect) EngineOption {
	return func(cfg *engineConfig) {
		cfg.defaultEffect = effect
	}
}

// CompileDocument converts a policy document into an executable engine.
func CompileDocument(doc Document, opts ...EngineOption) (*Engine, error) {
	cfg := engineConfig{
		defaultEffect: EffectDeny,
	}

	for _, opt := range opts {
		opt(&cfg)
	}

	engine := &Engine{
		defaultEffect: cfg.defaultEffect,
	}

	if doc.DefaultEffect != nil {
		engine.defaultEffect = *doc.DefaultEffect
	}

	if !engine.defaultEffect.IsValid() {
		return nil, fmt.Errorf("invalid default effect %q", engine.defaultEffect)
	}

	compiled := make([]*compiledPolicy, 0, len(doc.Policies))
	for idx := range doc.Policies {
		policy := doc.Policies[idx]
		cp, err := compilePolicy(policy, cfg)
		if err != nil {
			return nil, fmt.Errorf("compile policy %q: %w", policy.Name, err)
		}
		compiled = append(compiled, cp)
	}

	engine.policies = compiled

	return engine, nil
}

// CompilePolicies is a convenience helper when you already materialised policies.
func CompilePolicies(policies []Policy, opts ...EngineOption) (*Engine, error) {
	doc := Document{Policies: policies}
	return CompileDocument(doc, opts...)
}

// Evaluate runs all compiled policies against the provided context value.
// The final decision honours DENY over ALLOW, with a configurable default fallback.
func (e *Engine) Evaluate(_ context.Context, input any) Decision {
	decision := Decision{
		Effect:  e.defaultEffect,
		Message: "no rule matched; returning default effect",
	}

	if len(e.policies) == 0 {
		decision.Message = "no policies loaded; returning default effect"
		return decision
	}

	var allowDecision *Decision
	var firstErr error
	evaluated := 0

	for _, policy := range e.policies {
		policyMatched := false

		for _, rule := range policy.rules {
			evaluated++

			ok, err := rule.evaluate(input)
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}

			if !ok {
				continue
			}

			matchDecision := Decision{
				Effect:    rule.rule.Effect,
				Policy:    policy.policy.Name,
				Rule:      rule.rule.ID,
				Message:   rule.rule.Description,
				Matched:   true,
				Evaluated: evaluated,
			}

			if rule.rule.Effect == EffectDeny {
				matchDecision.Error = firstErr
				matchDecision.ErrorMessage = cleanErrorMessage(firstErr)
				return matchDecision
			}

			policyMatched = true

			if allowDecision == nil {
				cp := matchDecision
				allowDecision = &cp
			}
		}

		if !policyMatched && policy.hasLocalDefault {
			defaultDecision := Decision{
				Effect:       policy.defaultEffect,
				Policy:       policy.policy.Name,
				Message:      "policy default effect applied",
				Matched:      true,
				Evaluated:    evaluated,
				Error:        firstErr,
				ErrorMessage: cleanErrorMessage(firstErr),
			}

			if policy.defaultEffect == EffectDeny {
				return defaultDecision
			}

			if allowDecision == nil {
				cp := defaultDecision
				allowDecision = &cp
			}
		}
	}

	if allowDecision != nil {
		allowDecision.Error = firstErr
		allowDecision.ErrorMessage = cleanErrorMessage(firstErr)
		return *allowDecision
	}

	decision.Evaluated = evaluated
	decision.Error = firstErr
	decision.ErrorMessage = cleanErrorMessage(firstErr)
	return decision
}

type compiledPolicy struct {
	policy          Policy
	rules           []*compiledRule
	defaultEffect   Effect
	hasLocalDefault bool
}

type compiledRule struct {
	rule    Rule
	program *vm.Program
}

func compilePolicy(p Policy, cfg engineConfig) (*compiledPolicy, error) {
	if p.Name == "" {
		return nil, errors.New("policy name is required")
	}

	policyDefault := cfg.defaultEffect
	hasLocalDefault := false

	if p.DefaultEffect != nil {
		policyDefault = *p.DefaultEffect
		hasLocalDefault = true
	}

	if hasLocalDefault && !policyDefault.IsValid() {
		return nil, fmt.Errorf("policy %q has invalid default effect %q", p.Name, policyDefault)
	}

	if len(p.Rules) == 0 && !hasLocalDefault {
		return nil, fmt.Errorf("policy %q must include at least one rule or specify a default effect", p.Name)
	}

	rules := make([]*compiledRule, 0, len(p.Rules))

	for idx := range p.Rules {
		rule := p.Rules[idx]

		if rule.ID == "" {
			rule.ID = fmt.Sprintf("%s_rule_%d", p.Name, idx)
		}

		p.Rules[idx] = rule

		if !rule.Effect.IsValid() {
			return nil, fmt.Errorf("rule %q has invalid effect %q", rule.ID, rule.Effect)
		}

		if rule.Condition == "" {
			return nil, fmt.Errorf("rule %q condition cannot be empty", rule.ID)
		}

		opts := make([]expr.Option, 0, len(cfg.exprOptions)+3)
		opts = append(opts, cfg.exprOptions...)

		// Only allow undefined variables if strict types are disabled
		if !cfg.strictTypes {
			opts = append(opts, expr.AllowUndefinedVariables())
		}

		if cfg.env != nil {
			opts = append(opts, expr.Env(cfg.env))
		} else {
			opts = append(opts, expr.Env(map[string]any{}))
		}
		opts = append(opts, expr.AsBool())

		program, err := expr.Compile(rule.Condition, opts...)
		if err != nil {
			return nil, fmt.Errorf("compile rule %q: %w", rule.ID, err)
		}

		cr := &compiledRule{
			rule:    rule,
			program: program,
		}

		rules = append(rules, cr)
	}

	return &compiledPolicy{
		policy:          p,
		rules:           rules,
		defaultEffect:   policyDefault,
		hasLocalDefault: hasLocalDefault,
	}, nil
}

func (r *compiledRule) evaluate(input any) (bool, error) {
	output, err := expr.Run(r.program, input)
	if err != nil {
		return false, err
	}

	boolResult, ok := output.(bool)
	if !ok {
		return false, fmt.Errorf("rule %q did not return a boolean", r.rule.ID)
	}

	return boolResult, nil
}

// cleanErrorMessage converts technical expr errors into user-friendly messages
func cleanErrorMessage(err error) string {
	if err == nil {
		return ""
	}

	errStr := err.Error()

	// Remove the visual error pointer lines (contains | and ^)
	lines := strings.Split(errStr, "\n")
	var cleanLines []string
	for _, line := range lines {
		// Skip lines that are just formatting (contain only spaces, dots, |, ^)
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "|") || strings.HasPrefix(trimmed, ".") {
			continue
		}
		cleanLines = append(cleanLines, line)
	}

	if len(cleanLines) > 0 {
		return strings.Join(cleanLines, "; ")
	}

	return errStr
}
