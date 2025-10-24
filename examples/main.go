package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/fystack/programmable-policy-engine/policy"
	"github.com/shopspring/decimal"
)

// Define structs matching the transaction JSON structure
type User struct {
	ID       string `json:"id" expr:"id"`
	Username string `json:"username" expr:"username"`
	Email    string `json:"email" expr:"email"`
	Role     string `json:"role" expr:"role"`
}

type Asset struct {
	ID        string `json:"id" expr:"id"`
	Name      string `json:"name" expr:"name"`
	Symbol    string `json:"symbol" expr:"symbol"`
	Decimals  int    `json:"decimals" expr:"decimals"`
	LogoURL   string `json:"logo_url" expr:"logo_url"`
	Address   string `json:"address" expr:"address"`
	IsNative  bool   `json:"is_native" expr:"is_native"`
	NetworkID string `json:"network_id" expr:"network_id"`
	PriceUSD  string `json:"price_usd" expr:"price_usd"`
}

type Wallet struct {
	ID        string `json:"id" expr:"id"`
	Name      string `json:"name" expr:"name"`
	Threshold int    `json:"threshold" expr:"threshold"`
	Disabled  bool   `json:"disabled" expr:"disabled"`
}

type Network struct {
	ID              string `json:"id" expr:"id"`
	Name            string `json:"name" expr:"name"`
	IsEVM           bool   `json:"is_evm" expr:"is_evm"`
	ChainID         int    `json:"chain_id" expr:"chain_id"`
	ExplorerTx      string `json:"explorer_tx" expr:"explorer_tx"`
	ExplorerAddress string `json:"explorer_address" expr:"explorer_address"`
	LogoURL         string `json:"logo_url" expr:"logo_url"`
}

type Transaction struct {
	ID            string          `json:"id" expr:"id"`
	Status        string          `json:"status" expr:"status"`
	Amount        decimal.Decimal `json:"amount" expr:"amount"`
	AmountNumeric float64         `json:"amount_numeric" expr:"amount_numeric"` // We'll add this after parsing
	TxHash        *string         `json:"tx_hash" expr:"tx_hash"`
	FromAddress   string          `json:"from_address" expr:"from_address"`
	ToAddress     string          `json:"to_address" expr:"to_address"`
	Direction     string          `json:"direction" expr:"direction"`
	Type          string          `json:"type" expr:"type"`
	Method        string          `json:"method" expr:"method"`
	User          User            `json:"user" expr:"user"`
	Asset         Asset           `json:"asset" expr:"asset"`
	Wallet        Wallet          `json:"wallet" expr:"wallet"`
	Network       Network         `json:"network" expr:"network"`
}

type TransactionContext struct {
	Transaction Transaction `json:"transaction" expr:"transaction"`
}

func main() {
	doc, err := policy.LoadJSONDocument("examples/policies/transaction.json")
	if err != nil {
		log.Fatalf("load policy: %v", err)
	}

	// Use struct schema for type validation
	engine, err := policy.CompileDocument(doc, policy.WithSchemaDefinition(TransactionContext{}))
	if err != nil {
		log.Fatalf("compile policy: %v", err)
	}

	ctx, err := loadTransactionContext("examples/data/transaction.json")
	if err != nil {
		log.Fatalf("load transaction context: %v", err)
	}

	decision := engine.Evaluate(context.Background(), ctx)
	if decision.Error != nil {
		fmt.Printf("decision=%s policy=%s rule=%s error=%s\n", decision.Effect, decision.Policy, decision.Rule, decision.ErrorMessage)
		return
	}

	fmt.Printf("decision=%s policy=%s rule=%s message=%s\n", decision.Effect, decision.Policy, decision.Rule, decision.Message)
}

func loadTransactionContext(path string) (TransactionContext, error) {
	f, err := os.Open(path)
	if err != nil {
		return TransactionContext{}, err
	}
	defer f.Close()

	var envelope struct {
		Success bool          `json:"success"`
		Message string        `json:"message"`
		Code    int           `json:"code"`
		Data    []Transaction `json:"data"`
	}

	if err := json.NewDecoder(f).Decode(&envelope); err != nil {
		return TransactionContext{}, err
	}

	if len(envelope.Data) == 0 {
		return TransactionContext{}, fmt.Errorf("data array is empty")
	}

	transaction := envelope.Data[0]

	// Convert high-precision amount to float for AmountNumeric comparisons
	transaction.AmountNumeric = transaction.Amount.InexactFloat64()

	return TransactionContext{
		Transaction: transaction,
	}, nil
}
