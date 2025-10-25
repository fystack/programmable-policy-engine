# Programmable Policy Engine

This repository provides a programmable policy engine that helps wallets and treasury platforms evaluate high-volume transactions against configurable guardrails. Policies are defined as JSON documents and executed with the [expr](https://github.com/expr-lang/expr) expression language so teams can ship granular business logic without redeploying code.

Key use cases include:
- Enforcing transaction thresholds (e.g., stop withdrawals above a limit)
- Requiring additional reviews based on user role, network, or asset metadata
- Allowing fast approvals for trusted wallets while denying risky flows by default

## Features
- **Deterministic evaluations** powered by compiled expr programs
- **Default effects** at document and policy level with a DENY-overrides-ALLOW model
- **Strict schema validation** (optional) via `WithSchemaDefinition`
- **Friendly error reporting** that surfaces the failing rule and expression issue
- **Zero-config loader** for JSON policy documents

## Installation

```sh
go get github.com/fystack/programmable-policy-engine/policy
```

## Quick Start

The engine compiles policy documents into executable rules and evaluates them against any Go value (structs, maps, etc.).

```go
package main

import (
	"context"
	"fmt"

	"github.com/fystack/programmable-policy-engine/policy"
)

type TransactionContext struct {
	Amount float64
	User   struct {
		Role string
	}
}

func main() {
	defaultEffect := policy.EffectDeny

	doc := policy.Document{
		DefaultEffect: &defaultEffect, // deny by default when nothing matches
		Policies: []policy.Policy{
			{
				Name: "withdrawal-override",
				Rules: []policy.Rule{
					{
						ID:        "deny_large_withdrawals",
						Effect:    policy.EffectDeny,
						Condition: "Amount > 100",
					},
					{
						ID:        "allow_admin",
						Effect:    policy.EffectAllow,
						Condition: "Amount <= 100 && User.Role in ['admin', 'owner']",
					},
				},
			},
		},
	}

	engine, err := policy.CompileDocument(doc)
	if err != nil {
		panic(err)
	}

	ctx := TransactionContext{
		Amount: 90,
		User:   struct{ Role string }{Role: "admin"},
	}

	decision := engine.Evaluate(context.Background(), ctx)
	fmt.Printf("decision=%s policy=%s rule=%s message=%s\n",
		decision.Effect, decision.Policy, decision.Rule, decision.Message)
}
```

> You can also construct policy documents by loading JSON files from disk.

### Interpreting decisions at runtime

`Evaluate` always returns a `Decision`—check its fields to decide whether to continue:

```go
decision := engine.Evaluate(context.Background(), ctx)

switch {
case decision.Effect == policy.EffectAllow && decision.Matched:
	fmt.Println("ok to continue:", decision.Message)
case decision.Effect == policy.EffectAllow && !decision.Matched:
	fmt.Println("allow by document default (no rule matched); double-check audit requirements")
default:
	fmt.Println("stop:", decision.Effect, decision.Message)
	if decision.Error != nil {
		fmt.Println("expr error:", decision.ErrorMessage)
	}
}
```

`Matched` is true when a specific rule (or a policy-level default) triggered. If all policies fall back to the document default, `Matched` remains false but `Effect` still reflects the decision (`ALLOW` or `DENY`).

### Mapping snake_case JSON to expr fields

Use the `expr` struct tag to expose snake_case JSON fields with the same name inside expressions:

```go
type Transaction struct {
	AmountNumeric float64 `json:"amount_numeric" expr:"amount_numeric"`
	User          struct {
		RiskLevel string `json:"risk_level" expr:"risk_level"`
	} `json:"user" expr:"user"`
}

// In a rule: "transaction.amount_numeric <= 100 && transaction.user.risk_level == 'low'"
```

When paired with `policy.WithSchemaDefinition(Transaction{})`, the engine validates both the field names (`amount_numeric`, `risk_level`, etc.) and their types at compile time.

## Policy Document Structure

| Field | Type | Description |
| --- | --- | --- |
| `version` | string (optional) | Free-form version tag for tracking document revisions. |
| `default_effect` | `"ALLOW"` or `"DENY"` | Fallback effect when no rule matches. Defaults to `DENY`. |
| `policies[]` | array | Each policy groups related rules. Policies can also specify their own default effect. |
| `policies[].rules[]` | array | Individual rule definitions with an expression condition and an effect. |
| `rules[].metadata` | map (optional) | Arbitrary labels for audit trails or analytics. |

Expressions use the expr syntax and must return a boolean. The engine automatically injects your evaluation context (structs, maps) as the root object.

### Default effect in action

`default_effect` controls what happens when no rule matches or when a policy needs a fallback decision. Set it on the document to establish a global default, and optionally override it per policy (every policy must contain at least one rule or define its own `default_effect`):

```json
{
  "default_effect": "DENY",
  "policies": [
    {
      "name": "low-risk-fastlane",
      "default_effect": "ALLOW",
      "rules": [
        {
          "id": "deny_high_amount",
          "effect": "DENY",
          "condition": "transaction.amount_numeric > 1000"
        }
      ]
    }
  ]
}
```

With this document:
- A transaction over 1000 units returns `DENY` because the rule matches.
- Any other transaction yields `ALLOW` because the policy’s local default applies.
- If the policy were removed, the engine would fall back to the document-level `DENY`.
- Policies without rules must specify a `default_effect`; otherwise compilation fails.
- The behaviour is covered by unit tests such as `TestDefaultDenyWhenNoRulesMatch` and `TestPolicyDefaultEffectAppliedWhenNoRules` in `policy/engine_test.go`.

## End-to-End Example

The repository includes a full wallet transaction walkthrough under `examples/`:

1. **Policy document** (`examples/policies/transaction.json`) denies withdrawals above 100 units unless the user is trusted.
2. **Sample payload** (`examples/data/transaction.json`) mirrors a realistic transaction envelope from a wallet API.
3. **Runner** (`examples/main.go`) loads both the policy and payload, applies type validation with `WithSchemaDefinition`, and prints the decision.

Run the example:

```sh
go run ./examples
```

Example output:

```
decision=ALLOW policy=withdrawal-override rule=allow_small_admin_owner message=Allow admins or owners to move less than or equal to 100 units
```

## Designing Policies
- Start with a DENY default and add ALLOW rules for trusted scenarios.
- Use `metadata` to tag rules with ticket IDs, owners, or severity.
- Pair `WithSchemaDefinition` with Go structs to catch typos and type errors at compile time.
- Keep expressions immutable; prefer new policies over mutating existing ones when you need auditability.
- Every evaluation returns a `Decision` struct—inspect `decision.Matched` to see whether a rule (or policy default) fired, and use `decision.Policy`/`decision.Rule` plus the message to build your audit trail.

## Contributing

Issues and pull requests are welcome. Please include tests for new behavior; the existing suite lives under `policy/`.
