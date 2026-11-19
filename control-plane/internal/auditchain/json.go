package auditchain

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// RejectDuplicateJSONMembers detects duplicate object keys at every nesting
// level before decoding into Go structs, where duplicate keys would otherwise
// silently use the last value.
func RejectDuplicateJSONMembers(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var readValue func() error
	readValue = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]struct{}{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("JSON object key is invalid")
				}
				if _, duplicate := seen[key]; duplicate {
					return fmt.Errorf("duplicate JSON member %q", key)
				}
				seen[key] = struct{}{}
				if err := readValue(); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return errors.New("JSON object is invalid")
			}
		case '[':
			for decoder.More() {
				if err := readValue(); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return errors.New("JSON array is invalid")
			}
		default:
			return errors.New("JSON delimiter is invalid")
		}
		return nil
	}
	if err := readValue(); err != nil {
		return fmt.Errorf("validate JSON: %w", err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON has trailing data")
		}
		return fmt.Errorf("validate trailing JSON: %w", err)
	}
	return nil
}
