package policy

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// ParseJSONDocument decodes a policy document from JSON.
func ParseJSONDocument(r io.Reader) (Document, error) {
	var doc Document
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return Document{}, fmt.Errorf("decode policy document: %w", err)
	}
	return doc, nil
}

// LoadJSONDocument reads a JSON document from disk.
func LoadJSONDocument(path string) (Document, error) {
	f, err := os.Open(path)
	if err != nil {
		return Document{}, fmt.Errorf("open policy document: %w", err)
	}
	defer f.Close()
	return ParseJSONDocument(f)
}
