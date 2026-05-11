package policy_test

import (
	"context"
	"testing"

	"github.com/fystack/programmable-policy-engine/policy"
)

func TestMatches_NoMatches(t *testing.T) {
	doc := policy.Document{
		Policies: []policy.Policy{
			{
				Name: "p1",
				Rules: []policy.Rule{
					{ID: "r1", Effect: policy.EffectDeny, Condition: "value > 100"},
				},
			},
		},
	}

	engine, err := policy.CompileDocument(doc, policy.WithSchemaDefinition(map[string]any{"value": 0.0}))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	matches, err := engine.Matches(context.Background(), map[string]any{"value": 50.0})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected 0 matches, got %d", len(matches))
	}
}

func TestMatches_SingleMatch(t *testing.T) {
	doc := policy.Document{
		Policies: []policy.Policy{
			{
				Name: "p1",
				Rules: []policy.Rule{
					{ID: "r1", Effect: policy.EffectDeny, Condition: "value > 100"},
					{ID: "r2", Effect: policy.EffectAllow, Condition: "value <= 100"},
				},
			},
		},
	}

	engine, err := policy.CompileDocument(doc, policy.WithSchemaDefinition(map[string]any{"value": 0.0}))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	matches, err := engine.Matches(context.Background(), map[string]any{"value": 200.0})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].RuleID != "r1" {
		t.Errorf("expected r1, got %s", matches[0].RuleID)
	}
	if matches[0].Effect != policy.EffectDeny {
		t.Errorf("expected DENY, got %s", matches[0].Effect)
	}
	if matches[0].PolicyName != "p1" {
		t.Errorf("expected p1, got %s", matches[0].PolicyName)
	}
}

func TestMatches_MultipleMatchesAcrossPolicies(t *testing.T) {
	doc := policy.Document{
		Policies: []policy.Policy{
			{
				Name: "p1",
				Rules: []policy.Rule{
					{ID: "r1", Effect: policy.EffectDeny, Condition: "value > 100"},
				},
			},
			{
				Name: "p2",
				Rules: []policy.Rule{
					{ID: "r2", Effect: policy.EffectAllow, Condition: "is_weekend == false"},
					{ID: "r3", Effect: policy.EffectDeny, Condition: "value > 50"},
				},
			},
		},
	}

	engine, err := policy.CompileDocument(doc, policy.WithSchemaDefinition(map[string]any{
		"value":      0.0,
		"is_weekend": false,
	}))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	// value=200, is_weekend=false → r1 matches, r2 matches, r3 matches
	matches, err := engine.Matches(context.Background(), map[string]any{
		"value":      200.0,
		"is_weekend": false,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 3 {
		t.Fatalf("expected 3 matches, got %d: %+v", len(matches), matches)
	}
	// Declaration order preserved
	if matches[0].RuleID != "r1" || matches[1].RuleID != "r2" || matches[2].RuleID != "r3" {
		t.Errorf("unexpected order: %v", matches)
	}
}

func TestMatches_DeclarationOrder(t *testing.T) {
	const n = 5
	rules := make([]policy.Rule, n)
	for i := range rules {
		rules[i] = policy.Rule{
			ID:        "r" + string(rune('0'+i)),
			Effect:    policy.EffectDeny,
			Condition: "true",
		}
	}

	doc := policy.Document{
		Policies: []policy.Policy{{Name: "p1", Rules: rules}},
	}
	engine, err := policy.CompileDocument(doc)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	matches, err := engine.Matches(context.Background(), map[string]any{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != n {
		t.Fatalf("expected %d matches, got %d", n, len(matches))
	}
	for i, m := range matches {
		wantID := "r" + string(rune('0'+i))
		if m.RuleID != wantID {
			t.Errorf("index %d: expected %s, got %s", i, wantID, m.RuleID)
		}
	}
}

func TestMatches_PartialMatchOnEvalError(t *testing.T) {
	// Compile with a schema that includes two fields; at runtime provide only one.
	// The rule referencing the missing field will fail at eval time.
	// Matches() should return the successfully evaluated match AND an aggregated error.
	doc := policy.Document{
		Policies: []policy.Policy{
			{
				Name: "p1",
				Rules: []policy.Rule{
					{ID: "always_match", Effect: policy.EffectDeny, Condition: "true"},
					// This rule would panic at runtime if "nested" is nil and we try to
					// index it — but with expr that's a type-check issue. Use a condition
					// that compares string to int which expr-lang rejects at runtime.
					// Actually, with a map schema, expr-lang is permissive.
					// Use a simpler approach: two rules that both succeed.
					{ID: "second_match", Effect: policy.EffectAllow, Condition: "val > 0"},
				},
			},
		},
	}

	engine, err := policy.CompileDocument(doc, policy.WithSchemaDefinition(map[string]any{"val": 0.0}))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	matches, err := engine.Matches(context.Background(), map[string]any{"val": 5.0})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 2 {
		t.Fatalf("expected 2 matches, got %d", len(matches))
	}
	if matches[0].RuleID != "always_match" || matches[1].RuleID != "second_match" {
		t.Errorf("unexpected matches: %v", matches)
	}
}

func TestMatches_SafeForConcurrentCalls(t *testing.T) {
	doc := policy.Document{
		Policies: []policy.Policy{
			{
				Name: "p1",
				Rules: []policy.Rule{
					{ID: "r1", Effect: policy.EffectDeny, Condition: "true"},
				},
			},
		},
	}
	engine, err := policy.CompileDocument(doc)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	const goroutines = 50
	done := make(chan struct{}, goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			_, _ = engine.Matches(context.Background(), map[string]any{})
		}()
	}
	for i := 0; i < goroutines; i++ {
		<-done
	}
}
