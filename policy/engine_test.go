package policy_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/fystack/programmable-policy-engine/policy"
	"github.com/shopspring/decimal"
)

// Test structs for typed evaluation
type User struct {
	ID       string
	Username string
	Email    string
	Role     string
}

type Asset struct {
	Symbol   string
	Decimals int
	IsNative bool
}

type Transaction struct {
	ID            string
	Status        string
	Amount        decimal.Decimal
	AmountNumeric float64
	User          User
	Asset         Asset
}

type TransactionContext struct {
	Transaction Transaction
}

// Test structs with JSON tags (snake_case)
type UserWithTags struct {
	ID       string `json:"user_id"`
	Username string `json:"username"`
	Email    string `json:"email_address"`
	Role     string `json:"user_role"`
}

type AssetWithTags struct {
	Symbol   string `json:"asset_symbol"`
	Decimals int    `json:"decimals"`
	IsNative bool   `json:"is_native"`
	ChainID  int    `json:"chain_id"`
	PriceUSD string `json:"price_usd"`
}

type TransactionWithTags struct {
	ID            string          `json:"transaction_id"`
	Status        string          `json:"transaction_status"`
	Amount        decimal.Decimal `json:"amount"`
	AmountNumeric float64         `json:"amount_numeric"`
	TxHash        string          `json:"tx_hash"`
	FromAddress   string          `json:"from_address"`
	ToAddress     string          `json:"to_address"`
	User          UserWithTags    `json:"user"`
	Asset         AssetWithTags   `json:"asset"`
}

type ContextWithTags struct {
	Transaction TransactionWithTags `json:"transaction"`
}

func TestEngineDenyOverridesAllow(t *testing.T) {
	doc := policy.Document{
		DefaultEffect: ptr(policy.EffectDeny),
		Policies: []policy.Policy{
			{
				Name: "withdrawals",
				Rules: []policy.Rule{
					{
						ID:        "deny_failed",
						Effect:    policy.EffectDeny,
						Condition: `transaction.status == 'failed'`,
					},
					{
						ID:        "allow_small",
						Effect:    policy.EffectAllow,
						Condition: `transaction.amount_numeric <= 100`,
					},
				},
			},
		},
	}

	engine, err := policy.CompileDocument(doc, policy.WithSchemaDefinition(map[string]any{
		"transaction": map[string]any{},
	}))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	transaction := map[string]any{
		"status":          "failed",
		"amount_numeric":  42.0,
		"user":            map[string]any{"role": "admin"},
		"asset":           map[string]any{"symbol": "USDC"},
		"network":         map[string]any{"chain_id": 11155111},
		"wallet":          map[string]any{"name": "mpc 3"},
		"workspace":       nil,
		"additional_note": "failure should deny before amount check",
	}

	decision := engine.Evaluate(context.Background(), map[string]any{
		"transaction": transaction,
	})

	if decision.Effect != policy.EffectDeny {
		t.Fatalf("expected DENY, got %s", decision.Effect)
	}

	if !decision.Matched {
		t.Fatalf("expected a matched rule")
	}

	if decision.Rule != "deny_failed" {
		t.Fatalf("expected rule deny_failed, got %s", decision.Rule)
	}
}

func TestEngineAllowsWhenRulesMatch(t *testing.T) {
	doc := policy.Document{
		DefaultEffect: ptr(policy.EffectDeny),
		Policies: []policy.Policy{
			{
				Name: "withdrawals",
				Rules: []policy.Rule{
					{
						ID:        "deny_failed",
						Effect:    policy.EffectDeny,
						Condition: `transaction.status == 'failed'`,
					},
					{
						ID:        "allow_small_admin",
						Effect:    policy.EffectAllow,
						Condition: `transaction.amount_numeric <= 100 && transaction.user.role in ['admin', 'owner']`,
					},
				},
			},
		},
	}

	engine, err := policy.CompileDocument(doc, policy.WithSchemaDefinition(map[string]any{
		"transaction": map[string]any{},
	}))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	transaction := map[string]any{
		"status":         "pending",
		"amount_numeric": 75.5,
		"user":           map[string]any{"role": "owner"},
	}

	input := map[string]any{
		"transaction": transaction,
	}

	decision := engine.Evaluate(context.Background(), input)
	if decision.Effect != policy.EffectAllow {
		t.Fatalf("expected ALLOW, got %s", decision.Effect)
	}
}

func TestPolicyDefaultEffectAppliedWhenNoRules(t *testing.T) {
	defaultAllow := policy.EffectAllow
	doc := policy.Document{
		DefaultEffect: ptr(policy.EffectDeny),
		Policies: []policy.Policy{
			{
				Name:          "global-override",
				DefaultEffect: &defaultAllow,
			},
		},
	}

	engine, err := policy.CompileDocument(doc)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	decision := engine.Evaluate(context.Background(), map[string]any{})
	if decision.Effect != policy.EffectAllow {
		t.Fatalf("expected ALLOW from policy default, got %s", decision.Effect)
	}
}

func TestDefaultDenyWhenNoRulesMatch(t *testing.T) {
	doc := policy.Document{
		DefaultEffect: ptr(policy.EffectDeny),
		Policies: []policy.Policy{
			{
				Name: "strict-policy",
				Rules: []policy.Rule{
					{
						ID:        "allow_admin_only",
						Effect:    policy.EffectAllow,
						Condition: `transaction.user.role == 'admin'`,
					},
				},
			},
		},
	}

	engine, err := policy.CompileDocument(doc, policy.WithSchemaDefinition(map[string]any{
		"transaction": map[string]any{},
	}))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	// Transaction from a regular user (not admin)
	transaction := map[string]any{
		"status":         "pending",
		"amount_numeric": 50.0,
		"user":           map[string]any{"role": "user"},
	}

	decision := engine.Evaluate(context.Background(), map[string]any{
		"transaction": transaction,
	})

	if decision.Effect != policy.EffectDeny {
		t.Fatalf("expected DENY when no rules match, got %s", decision.Effect)
	}

	if decision.Matched {
		t.Fatalf("expected no matched rule, but got matched=true")
	}

	if decision.Message != "no rule matched; returning default effect" {
		t.Fatalf("expected default message, got: %s", decision.Message)
	}
}

func TestEmptyPolicyDocument(t *testing.T) {
	doc := policy.Document{
		DefaultEffect: ptr(policy.EffectDeny),
		Policies:      []policy.Policy{},
	}

	engine, err := policy.CompileDocument(doc)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	decision := engine.Evaluate(context.Background(), map[string]any{
		"transaction": map[string]any{"amount": 100},
	})

	if decision.Effect != policy.EffectDeny {
		t.Fatalf("expected DENY with no policies, got %s", decision.Effect)
	}

	if decision.Matched {
		t.Fatalf("expected no matched rule with empty policies")
	}

	if decision.Message != "no policies loaded; returning default effect" {
		t.Fatalf("expected 'no policies loaded' message, got: %s", decision.Message)
	}
}

func TestImplicitDefaultDeny(t *testing.T) {
	// Don't set DefaultEffect - should default to DENY
	doc := policy.Document{
		Policies: []policy.Policy{
			{
				Name: "test-policy",
				Rules: []policy.Rule{
					{
						ID:        "allow_large_amounts",
						Effect:    policy.EffectAllow,
						Condition: `transaction.amount_numeric > 1000`,
					},
				},
			},
		},
	}

	engine, err := policy.CompileDocument(doc, policy.WithSchemaDefinition(map[string]any{
		"transaction": map[string]any{},
	}))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	// Small transaction that doesn't match the rule
	transaction := map[string]any{
		"amount_numeric": 100.0,
	}

	decision := engine.Evaluate(context.Background(), map[string]any{
		"transaction": transaction,
	})

	if decision.Effect != policy.EffectDeny {
		t.Fatalf("expected implicit DENY default, got %s", decision.Effect)
	}

	if decision.Matched {
		t.Fatalf("expected no matched rule")
	}
}

func TestDenyAllWithNoRules(t *testing.T) {
	// Policy with no rules and explicit DENY default
	denyEffect := policy.EffectDeny
	doc := policy.Document{
		Policies: []policy.Policy{
			{
				Name:          "deny-all",
				DefaultEffect: &denyEffect,
			},
		},
	}

	engine, err := policy.CompileDocument(doc)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	decision := engine.Evaluate(context.Background(), map[string]any{
		"transaction": map[string]any{"amount": 999999},
	})

	if decision.Effect != policy.EffectDeny {
		t.Fatalf("expected DENY from policy default, got %s", decision.Effect)
	}

	if !decision.Matched {
		t.Fatalf("expected matched=true when policy default is applied")
	}

	if decision.Policy != "deny-all" {
		t.Fatalf("expected policy name 'deny-all', got %s", decision.Policy)
	}

	if decision.Message != "policy default effect applied" {
		t.Fatalf("expected 'policy default effect applied' message, got: %s", decision.Message)
	}
}

func TestStructWithFloatComparison(t *testing.T) {
	doc := policy.Document{
		DefaultEffect: ptr(policy.EffectDeny),
		Policies: []policy.Policy{
			{
				Name: "withdrawal-limits",
				Rules: []policy.Rule{
					{
						ID:        "deny_large_withdrawal",
						Effect:    policy.EffectDeny,
						Condition: `Transaction.AmountNumeric > 100.23`,
					},
					{
						ID:        "allow_small_withdrawal",
						Effect:    policy.EffectAllow,
						Condition: `Transaction.AmountNumeric <= 100.23 && Transaction.User.Role == 'admin'`,
					},
				},
			},
		},
	}

	engine, err := policy.CompileDocument(doc, policy.WithSchemaDefinition(TransactionContext{}))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	// Test case 1: Amount exactly at limit (100.23) - should ALLOW for admin
	ctx1 := TransactionContext{
		Transaction: Transaction{
			ID:            "tx-001",
			Status:        "pending",
			Amount:        decimal.RequireFromString("100.23"),
			AmountNumeric: 100.23,
			User: User{
				ID:       "user-001",
				Username: "admin-user",
				Role:     "admin",
			},
			Asset: Asset{
				Symbol:   "USDC",
				Decimals: 6,
				IsNative: false,
			},
		},
	}

	decision := engine.Evaluate(context.Background(), ctx1)
	if decision.Effect != policy.EffectAllow {
		t.Fatalf("expected ALLOW for amount=100.23 with admin, got %s", decision.Effect)
	}
	if decision.Rule != "allow_small_withdrawal" {
		t.Fatalf("expected rule 'allow_small_withdrawal', got %s", decision.Rule)
	}

	// Test case 2: Amount above limit (100.24) - should DENY
	ctx2 := TransactionContext{
		Transaction: Transaction{
			ID:            "tx-002",
			Status:        "pending",
			Amount:        decimal.RequireFromString("100.24"),
			AmountNumeric: 100.24,
			User: User{
				ID:       "user-001",
				Username: "admin-user",
				Role:     "admin",
			},
			Asset: Asset{
				Symbol:   "USDC",
				Decimals: 6,
				IsNative: false,
			},
		},
	}

	decision = engine.Evaluate(context.Background(), ctx2)
	if decision.Effect != policy.EffectDeny {
		t.Fatalf("expected DENY for amount=100.24, got %s", decision.Effect)
	}
	if decision.Rule != "deny_large_withdrawal" {
		t.Fatalf("expected rule 'deny_large_withdrawal', got %s", decision.Rule)
	}

	// Test case 3: Small amount (50.50) but non-admin - should DENY (no match)
	ctx3 := TransactionContext{
		Transaction: Transaction{
			ID:            "tx-003",
			Status:        "pending",
			Amount:        decimal.RequireFromString("50.50"),
			AmountNumeric: 50.50,
			User: User{
				ID:       "user-002",
				Username: "regular-user",
				Role:     "user",
			},
			Asset: Asset{
				Symbol:   "USDC",
				Decimals: 6,
				IsNative: false,
			},
		},
	}

	decision = engine.Evaluate(context.Background(), ctx3)
	if decision.Effect != policy.EffectDeny {
		t.Fatalf("expected DENY for non-admin user, got %s", decision.Effect)
	}
	if decision.Matched {
		t.Fatalf("expected no matched rule for non-admin")
	}
}

func TestStructWithNestedFieldAccess(t *testing.T) {
	doc := policy.Document{
		DefaultEffect: ptr(policy.EffectDeny),
		Policies: []policy.Policy{
			{
				Name: "asset-restrictions",
				Rules: []policy.Rule{
					{
						ID:        "allow_usdc_for_verified",
						Effect:    policy.EffectAllow,
						Condition: `Transaction.Asset.Symbol == 'USDC' && Transaction.User.Email != ''`,
					},
					{
						ID:        "deny_native_assets",
						Effect:    policy.EffectDeny,
						Condition: `Transaction.Asset.IsNative == true`,
					},
				},
			},
		},
	}

	engine, err := policy.CompileDocument(doc, policy.WithSchemaDefinition(TransactionContext{}))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	// Test nested struct field access
	ctx := TransactionContext{
		Transaction: Transaction{
			ID:            "tx-004",
			Status:        "pending",
			AmountNumeric: 75.99,
			User: User{
				ID:       "user-003",
				Username: "verified-user",
				Email:    "user@example.com",
				Role:     "user",
			},
			Asset: Asset{
				Symbol:   "USDC",
				Decimals: 6,
				IsNative: false,
			},
		},
	}

	decision := engine.Evaluate(context.Background(), ctx)
	if decision.Effect != policy.EffectAllow {
		t.Fatalf("expected ALLOW for USDC with verified user, got %s", decision.Effect)
	}
	if decision.Rule != "allow_usdc_for_verified" {
		t.Fatalf("expected rule 'allow_usdc_for_verified', got %s", decision.Rule)
	}

	// Test deny for native asset
	ctx2 := TransactionContext{
		Transaction: Transaction{
			ID:            "tx-005",
			Status:        "pending",
			AmountNumeric: 10.0,
			User: User{
				ID:       "user-003",
				Username: "verified-user",
				Email:    "user@example.com",
				Role:     "user",
			},
			Asset: Asset{
				Symbol:   "ETH",
				Decimals: 18,
				IsNative: true,
			},
		},
	}

	decision = engine.Evaluate(context.Background(), ctx2)
	if decision.Effect != policy.EffectDeny {
		t.Fatalf("expected DENY for native asset, got %s", decision.Effect)
	}
	if decision.Rule != "deny_native_assets" {
		t.Fatalf("expected rule 'deny_native_assets', got %s", decision.Rule)
	}
}

func TestStructWithPreciseFloatComparisons(t *testing.T) {
	doc := policy.Document{
		Policies: []policy.Policy{
			{
				Name: "precise-limits",
				Rules: []policy.Rule{
					{
						ID:        "tier1",
						Effect:    policy.EffectAllow,
						Condition: `Transaction.AmountNumeric <= 99.99`,
					},
					{
						ID:        "tier2",
						Effect:    policy.EffectAllow,
						Condition: `Transaction.AmountNumeric > 99.99 && Transaction.AmountNumeric <= 999.99`,
					},
					{
						ID:        "tier3_deny",
						Effect:    policy.EffectDeny,
						Condition: `Transaction.AmountNumeric > 999.99`,
					},
				},
			},
		},
	}

	engine, err := policy.CompileDocument(doc, policy.WithSchemaDefinition(TransactionContext{}))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	testCases := []struct {
		amount         float64
		expectedEffect policy.Effect
		expectedRule   string
		description    string
	}{
		{50.00, policy.EffectAllow, "tier1", "tier1 boundary"},
		{99.99, policy.EffectAllow, "tier1", "tier1 max"},
		{100.00, policy.EffectAllow, "tier2", "tier2 min"},
		{500.50, policy.EffectAllow, "tier2", "tier2 mid"},
		{999.99, policy.EffectAllow, "tier2", "tier2 max"},
		{1000.00, policy.EffectDeny, "tier3_deny", "tier3 min"},
		{9999.99, policy.EffectDeny, "tier3_deny", "tier3 high"},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			ctx := TransactionContext{
				Transaction: Transaction{
					AmountNumeric: tc.amount,
					Status:        "pending",
					User:          User{Role: "user"},
					Asset:         Asset{Symbol: "USDT"},
				},
			}

			decision := engine.Evaluate(context.Background(), ctx)
			if decision.Effect != tc.expectedEffect {
				t.Errorf("amount=%.2f: expected %s, got %s", tc.amount, tc.expectedEffect, decision.Effect)
			}
			if decision.Rule != tc.expectedRule {
				t.Errorf("amount=%.2f: expected rule %s, got %s", tc.amount, tc.expectedRule, decision.Rule)
			}
		})
	}
}

func TestJSONWithSnakeCaseFieldNames(t *testing.T) {
	// JSON data with snake_case field names
	jsonData := `{
		"transaction": {
			"transaction_id": "tx-123",
			"transaction_status": "pending",
			"amount_numeric": 150.75,
			"tx_hash": "0xabcdef",
			"user": {
				"user_id": "user-456",
				"user_role": "admin",
				"email_address": "admin@example.com"
			},
			"asset": {
				"asset_symbol": "USDC",
				"is_native": false,
				"chain_id": 11155111
			}
		}
	}`

	// Use snake_case field names in conditions (matches JSON keys)
	doc := policy.Document{
		DefaultEffect: ptr(policy.EffectDeny),
		Policies: []policy.Policy{
			{
				Name: "snake-case-policy",
				Rules: []policy.Rule{
					{
						ID:        "deny_large_amounts",
						Effect:    policy.EffectDeny,
						Condition: `transaction.amount_numeric > 200.00`,
					},
					{
						ID:        "allow_admin_medium",
						Effect:    policy.EffectAllow,
						Condition: `transaction.user.user_role == 'admin' && transaction.amount_numeric <= 200.00`,
					},
				},
			},
		},
	}

	// Use map[string]any as environment (no struct)
	engine, err := policy.CompileDocument(doc, policy.WithSchemaDefinition(map[string]any{
		"transaction": map[string]any{},
	}))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	// Unmarshal JSON into map (preserves snake_case keys)
	var data map[string]any
	if err := json.Unmarshal([]byte(jsonData), &data); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Evaluate using map data
	decision := engine.Evaluate(context.Background(), data)
	if decision.Effect != policy.EffectAllow {
		t.Fatalf("expected ALLOW for admin with amount=150.75, got %s", decision.Effect)
	}
	if decision.Rule != "allow_admin_medium" {
		t.Fatalf("expected rule 'allow_admin_medium', got %s", decision.Rule)
	}
}

func TestSnakeCaseWithPreciseFloats(t *testing.T) {
	doc := policy.Document{
		Policies: []policy.Policy{
			{
				Name: "float-precision-snake-case",
				Rules: []policy.Rule{
					{
						ID:        "tier1",
						Effect:    policy.EffectAllow,
						Condition: `transaction.amount_numeric <= 100.23`,
					},
					{
						ID:        "tier2",
						Effect:    policy.EffectAllow,
						Condition: `transaction.amount_numeric > 100.23 && transaction.amount_numeric < 1000.00`,
					},
					{
						ID:        "tier3",
						Effect:    policy.EffectDeny,
						Condition: `transaction.amount_numeric >= 1000.00`,
					},
				},
			},
		},
	}

	engine, err := policy.CompileDocument(doc, policy.WithSchemaDefinition(map[string]any{
		"transaction": map[string]any{},
	}))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	testCases := []struct {
		amount         float64
		expectedEffect policy.Effect
		expectedRule   string
		description    string
	}{
		{100.23, policy.EffectAllow, "tier1", "exact 100.23"},
		{100.22, policy.EffectAllow, "tier1", "below by 0.01"},
		{100.24, policy.EffectAllow, "tier2", "above by 0.01"},
		{50.50, policy.EffectAllow, "tier1", "half amount"},
		{999.99, policy.EffectAllow, "tier2", "tier2 max"},
		{1000.00, policy.EffectDeny, "tier3", "tier3 min"},
		{1500.75, policy.EffectDeny, "tier3", "high amount"},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			jsonData := fmt.Sprintf(`{
				"transaction": {
					"transaction_status": "pending",
					"amount_numeric": %f,
					"user": {"user_role": "user"},
					"asset": {"asset_symbol": "USDT"}
				}
			}`, tc.amount)

			var data map[string]any
			if err := json.Unmarshal([]byte(jsonData), &data); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}

			decision := engine.Evaluate(context.Background(), data)
			if decision.Effect != tc.expectedEffect {
				t.Errorf("amount=%.2f: expected %s, got %s", tc.amount, tc.expectedEffect, decision.Effect)
			}
			if decision.Rule != tc.expectedRule {
				t.Errorf("amount=%.2f: expected rule %s, got %s", tc.amount, tc.expectedRule, decision.Rule)
			}
		})
	}
}

func TestSnakeCaseNestedFields(t *testing.T) {
	jsonData := `{
		"transaction": {
			"transaction_id": "tx-789",
			"transaction_status": "failed",
			"amount_numeric": 75.50,
			"tx_hash": "0x123",
			"user": {
				"user_id": "user-999",
				"user_role": "owner",
				"email_address": "owner@example.com"
			},
			"asset": {
				"asset_symbol": "ETH",
				"is_native": true,
				"chain_id": 1,
				"decimals": 18
			}
		}
	}`

	doc := policy.Document{
		DefaultEffect: ptr(policy.EffectDeny),
		Policies: []policy.Policy{
			{
				Name: "nested-snake-case",
				Rules: []policy.Rule{
					{
						ID:        "deny_failed",
						Effect:    policy.EffectDeny,
						Condition: `transaction.transaction_status == 'failed'`,
					},
					{
						ID:        "allow_native_mainnet",
						Effect:    policy.EffectAllow,
						Condition: `transaction.asset.is_native == true && transaction.asset.chain_id == 1`,
					},
					{
						ID:        "check_email",
						Effect:    policy.EffectAllow,
						Condition: `transaction.user.email_address != '' && transaction.user.user_role == 'owner'`,
					},
				},
			},
		},
	}

	engine, err := policy.CompileDocument(doc, policy.WithSchemaDefinition(map[string]any{
		"transaction": map[string]any{},
	}))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	var data map[string]any
	if err := json.Unmarshal([]byte(jsonData), &data); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	decision := engine.Evaluate(context.Background(), data)
	if decision.Effect != policy.EffectDeny {
		t.Fatalf("expected DENY for failed status, got %s", decision.Effect)
	}
	if decision.Rule != "deny_failed" {
		t.Fatalf("expected rule 'deny_failed', got %s", decision.Rule)
	}
}

func TestSnakeCaseWithBooleanAndIntFields(t *testing.T) {
	doc := policy.Document{
		DefaultEffect: ptr(policy.EffectDeny),
		Policies: []policy.Policy{
			{
				Name: "complex-types",
				Rules: []policy.Rule{
					{
						ID:        "allow_usdc_sepolia",
						Effect:    policy.EffectAllow,
						Condition: `transaction.asset.asset_symbol == 'USDC' && transaction.asset.chain_id == 11155111`,
					},
					{
						ID:        "deny_native_assets",
						Effect:    policy.EffectDeny,
						Condition: `transaction.asset.is_native == true`,
					},
					{
						ID:        "allow_verified_user",
						Effect:    policy.EffectAllow,
						Condition: `transaction.user.email_address != '' && transaction.amount_numeric <= 100.23`,
					},
				},
			},
		},
	}

	engine, err := policy.CompileDocument(doc, policy.WithSchemaDefinition(map[string]any{
		"transaction": map[string]any{},
	}))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	// Test case: USDC on Sepolia with verified user
	jsonData := `{
		"transaction": {
			"transaction_status": "pending",
			"amount_numeric": 95.50,
			"user": {
				"user_role": "user",
				"email_address": "verified@example.com"
			},
			"asset": {
				"asset_symbol": "USDC",
				"is_native": false,
				"chain_id": 11155111,
				"decimals": 6
			}
		}
	}`

	var data map[string]any
	if err := json.Unmarshal([]byte(jsonData), &data); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	decision := engine.Evaluate(context.Background(), data)
	if decision.Effect != policy.EffectAllow {
		t.Fatalf("expected ALLOW for USDC on Sepolia, got %s", decision.Effect)
	}
	if decision.Rule != "allow_usdc_sepolia" {
		t.Fatalf("expected rule 'allow_usdc_sepolia', got %s", decision.Rule)
	}
}

func TestPassStructDirectlyWithSnakeCaseAccess(t *testing.T) {
	// Create struct directly (no marshal/unmarshal)
	ctx := ContextWithTags{
		Transaction: TransactionWithTags{
			ID:            "tx-direct-001",
			Status:        "pending",
			AmountNumeric: 100.23,
			TxHash:        "0xabc",
			FromAddress:   "0x111",
			ToAddress:     "0x222",
			User: UserWithTags{
				ID:       "user-direct-001",
				Username: "admin-user",
				Email:    "admin@example.com",
				Role:     "admin",
			},
			Asset: AssetWithTags{
				Symbol:   "USDC",
				Decimals: 6,
				IsNative: false,
				ChainID:  11155111,
				PriceUSD: "1.00",
			},
		},
	}

	// PROBLEM: With struct, you must use Go field names (PascalCase)
	// JSON tags don't affect runtime field access
	doc := policy.Document{
		DefaultEffect: ptr(policy.EffectDeny),
		Policies: []policy.Policy{
			{
				Name: "struct-direct-policy",
				Rules: []policy.Rule{
					{
						ID:     "allow_admin_exact_limit",
						Effect: policy.EffectAllow,
						// Must use Go field names, NOT JSON tags
						Condition: `Transaction.User.Role == 'admin' && Transaction.AmountNumeric <= 100.23`,
					},
				},
			},
		},
	}

	engine, err := policy.CompileDocument(doc, policy.WithSchemaDefinition(ContextWithTags{}))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	// Pass struct directly - NO marshal/unmarshal needed!
	decision := engine.Evaluate(context.Background(), ctx)
	if decision.Effect != policy.EffectAllow {
		t.Fatalf("expected ALLOW for direct struct, got %s", decision.Effect)
	}
	if decision.Rule != "allow_admin_exact_limit" {
		t.Fatalf("expected rule 'allow_admin_exact_limit', got %s", decision.Rule)
	}
}

func TestStructToMapForSnakeCaseAccess(t *testing.T) {
	// If you WANT to use snake_case field names in conditions,
	// you need to convert struct to map via JSON marshal/unmarshal

	// Step 1: Create struct
	ctx := ContextWithTags{
		Transaction: TransactionWithTags{
			ID:            "tx-convert-001",
			Status:        "failed",
			AmountNumeric: 75.50,
			User: UserWithTags{
				Role: "user",
			},
			Asset: AssetWithTags{
				Symbol:   "ETH",
				IsNative: true,
				ChainID:  1,
			},
		},
	}

	// Step 2: Marshal to JSON
	jsonBytes, err := json.Marshal(ctx)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Step 3: Unmarshal to map (this converts field names to JSON tags)
	var data map[string]any
	if err := json.Unmarshal(jsonBytes, &data); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Now you can use snake_case field names!
	doc := policy.Document{
		DefaultEffect: ptr(policy.EffectDeny),
		Policies: []policy.Policy{
			{
				Name: "snake-case-via-conversion",
				Rules: []policy.Rule{
					{
						ID:     "deny_failed_transactions",
						Effect: policy.EffectDeny,
						// Use JSON tag names (snake_case)
						Condition: `transaction.transaction_status == 'failed'`,
					},
					{
						ID:        "check_native_asset",
						Effect:    policy.EffectAllow,
						Condition: `transaction.asset.is_native == true && transaction.asset.chain_id == 1`,
					},
				},
			},
		},
	}

	engine, err := policy.CompileDocument(doc, policy.WithSchemaDefinition(map[string]any{
		"transaction": map[string]any{},
	}))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	decision := engine.Evaluate(context.Background(), data)
	if decision.Effect != policy.EffectDeny {
		t.Fatalf("expected DENY for failed transaction, got %s", decision.Effect)
	}
	if decision.Rule != "deny_failed_transactions" {
		t.Fatalf("expected rule 'deny_failed_transactions', got %s", decision.Rule)
	}
}

func TestComparisonStructVsMapAccess(t *testing.T) {
	// This test demonstrates the difference between struct and map access

	// Create a struct
	structCtx := ContextWithTags{
		Transaction: TransactionWithTags{
			Status:        "pending",
			AmountNumeric: 100.23,
			User:          UserWithTags{Role: "admin"},
			Asset:         AssetWithTags{Symbol: "USDC", IsNative: false},
		},
	}

	// Convert to map via JSON
	jsonBytes, _ := json.Marshal(structCtx)
	var mapData map[string]any
	json.Unmarshal(jsonBytes, &mapData)

	// Test 1: Using struct with PascalCase field names
	docStruct := policy.Document{
		Policies: []policy.Policy{
			{
				Name: "struct-access",
				Rules: []policy.Rule{
					{
						ID:        "rule1",
						Effect:    policy.EffectAllow,
						Condition: `Transaction.User.Role == 'admin'`, // PascalCase
					},
				},
			},
		},
	}

	engineStruct, _ := policy.CompileDocument(docStruct, policy.WithSchemaDefinition(ContextWithTags{}))
	decisionStruct := engineStruct.Evaluate(context.Background(), structCtx)

	if decisionStruct.Effect != policy.EffectAllow {
		t.Fatalf("struct access failed: got %s", decisionStruct.Effect)
	}

	// Test 2: Using map with snake_case field names
	docMap := policy.Document{
		Policies: []policy.Policy{
			{
				Name: "map-access",
				Rules: []policy.Rule{
					{
						ID:        "rule2",
						Effect:    policy.EffectAllow,
						Condition: `transaction.user.user_role == 'admin'`, // snake_case
					},
				},
			},
		},
	}

	engineMap, _ := policy.CompileDocument(docMap, policy.WithSchemaDefinition(map[string]any{
		"transaction": map[string]any{},
	}))
	decisionMap := engineMap.Evaluate(context.Background(), mapData)

	if decisionMap.Effect != policy.EffectAllow {
		t.Fatalf("map access failed: got %s", decisionMap.Effect)
	}

	// Both approaches work, just with different field name conventions!
}

func TestDecimalComparisonAllowsHighPrecision(t *testing.T) {
	doc := policy.Document{
		DefaultEffect: ptr(policy.EffectDeny),
		Policies: []policy.Policy{
			{
				Name: "decimal-precision",
				Rules: []policy.Rule{
					{
						ID:        "allow_when_amount_exceeds_limit",
						Effect:    policy.EffectAllow,
						Condition: `Transaction.Amount.GreaterThan(Transaction.Limit)`,
					},
				},
			},
		},
	}

	type decimalTransaction struct {
		Amount decimal.Decimal
		Limit  decimal.Decimal
	}

	type decimalContext struct {
		Transaction decimalTransaction
	}

	engine, err := policy.CompileDocument(doc, policy.WithSchemaDefinition(decimalContext{}))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	ctx := decimalContext{
		Transaction: decimalTransaction{
			Amount: decimal.RequireFromString("1.0000000000000001"),
			Limit:  decimal.RequireFromString("1.0"),
		},
	}

	decision := engine.Evaluate(context.Background(), ctx)
	if decision.Effect != policy.EffectAllow {
		t.Fatalf("expected ALLOW for high precision amount, got %s", decision.Effect)
	}

	ctx.Transaction.Amount = decimal.RequireFromString("0.9999999999999999")

	decision = engine.Evaluate(context.Background(), ctx)
	if decision.Effect != policy.EffectDeny {
		t.Fatalf("expected DENY when amount is below limit, got %s", decision.Effect)
	}
}

func ptr[T any](value T) *T {
	return &value
}
