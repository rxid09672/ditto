package malleable

/*
	Malleable C2 Transform Library
	Streamlined implementation following Cobalt Strike architecture
*/

import (
	"bytes"
	"encoding/base64"
	"fmt"
)

// ExecutePipeline applies a forward transform pipeline to data
// Skips termination actions (header, parameter, etc.) - those are handled separately
func ExecutePipeline(pipeline []Function, data []byte) ([]byte, error) {
	current := data

	for i, step := range pipeline {
		// Skip termination actions - they define placement, not transforms
		if IsTerminationAction(step.Func) {
			continue
		}

		// Execute transform
		result, err := ExecuteTransform(step.Func, step.Args, current)
		if err != nil {
			return nil, fmt.Errorf("pipeline step %d (%s) failed: %w", i+1, step.Func, err)
		}
		current = result
	}

	return current, nil
}

// ReversePipeline applies reverse transforms in reverse order
// This is used server-side to extract the original data from transformed requests
func ReversePipeline(pipeline []Function, data []byte) ([]byte, error) {
	current := data

	// Process in reverse order, skipping termination actions
	for i := len(pipeline) - 1; i >= 0; i-- {
		step := pipeline[i]

		// Skip termination actions
		if IsTerminationAction(step.Func) {
			continue
		}

		// Execute reverse transform
		result, err := ReverseTransform(step.Func, step.Args, current)
		if err != nil {
			return nil, fmt.Errorf("reverse pipeline step %d (%s) failed: %w", i+1, step.Func, err)
		}
		current = result
	}

	return current, nil
}

// ExtractTerminationAction finds and extracts the termination action from a pipeline
// Returns nil if no termination action is found
func ExtractTerminationAction(pipeline []Function) *TerminationAction {
	for _, step := range pipeline {
		if IsTerminationAction(step.Func) {
			arg := ""
			if len(step.Args) > 0 {
				arg = step.Args[0]
			}
			return &TerminationAction{
				Type: step.Func,
				Arg:  arg,
			}
		}
	}
	return nil
}

// IsTerminationAction checks if a function is a termination action
// (header, parameter, uri-append, print) rather than a data transform
func IsTerminationAction(funcName string) bool {
	terminators := []string{"header", "parameter", "uri-append", "print"}
	for _, t := range terminators {
		if funcName == t {
			return true
		}
	}
	return false
}

// ExecuteTransform applies a single transform to data
func ExecuteTransform(funcName string, args []string, data []byte) ([]byte, error) {
	switch funcName {
	case "base64":
		return TransformBase64(data), nil
	case "base64url":
		return TransformBase64URL(data), nil
	case "prepend":
		if len(args) < 1 {
			return nil, fmt.Errorf("prepend requires 1 argument")
		}
		return TransformPrepend(data, args[0]), nil
	case "append":
		if len(args) < 1 {
			return nil, fmt.Errorf("append requires 1 argument")
		}
		return TransformAppend(data, args[0]), nil
	default:
		return nil, fmt.Errorf("unsupported transform: %s", funcName)
	}
}

// ReverseTransform reverses a single transform on data
func ReverseTransform(funcName string, args []string, data []byte) ([]byte, error) {
	switch funcName {
	case "base64":
		return ReverseBase64(data)
	case "base64url":
		return ReverseBase64URL(data)
	case "prepend":
		if len(args) < 1 {
			return nil, fmt.Errorf("prepend requires 1 argument")
		}
		return ReversePrepend(data, args[0])
	case "append":
		if len(args) < 1 {
			return nil, fmt.Errorf("append requires 1 argument")
		}
		return ReverseAppend(data, args[0])
	default:
		return nil, fmt.Errorf("unsupported transform: %s", funcName)
	}
}

// ============================================================================
// Transform Implementations
// ============================================================================

// TransformBase64 encodes data using standard Base64 encoding
func TransformBase64(data []byte) []byte {
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(encoded, data)
	return encoded
}

// ReverseBase64 decodes standard Base64 encoded data
func ReverseBase64(data []byte) ([]byte, error) {
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
	n, err := base64.StdEncoding.Decode(decoded, data)
	if err != nil {
		return nil, fmt.Errorf("base64 decode failed: %w", err)
	}
	return decoded[:n], nil
}

// TransformBase64URL encodes data using URL-safe Base64 encoding
func TransformBase64URL(data []byte) []byte {
	encoded := make([]byte, base64.URLEncoding.EncodedLen(len(data)))
	base64.URLEncoding.Encode(encoded, data)
	return encoded
}

// ReverseBase64URL decodes URL-safe Base64 encoded data
func ReverseBase64URL(data []byte) ([]byte, error) {
	decoded := make([]byte, base64.URLEncoding.DecodedLen(len(data)))
	n, err := base64.URLEncoding.Decode(decoded, data)
	if err != nil {
		return nil, fmt.Errorf("base64url decode failed: %w", err)
	}
	return decoded[:n], nil
}

// TransformPrepend adds a string prefix to data
func TransformPrepend(data []byte, prefix string) []byte {
	return append([]byte(prefix), data...)
}

// ReversePrepend removes a string prefix from data
func ReversePrepend(data []byte, prefix string) ([]byte, error) {
	prefixBytes := []byte(prefix)
	if len(data) < len(prefixBytes) {
		return nil, fmt.Errorf("data too short for prefix (expected at least %d bytes, got %d)", len(prefixBytes), len(data))
	}
	if !bytes.HasPrefix(data, prefixBytes) {
		return nil, fmt.Errorf("data does not have expected prefix")
	}
	return data[len(prefixBytes):], nil
}

// TransformAppend adds a string suffix to data
func TransformAppend(data []byte, suffix string) []byte {
	return append(data, []byte(suffix)...)
}

// ReverseAppend removes a string suffix from data
func ReverseAppend(data []byte, suffix string) ([]byte, error) {
	suffixBytes := []byte(suffix)
	if len(data) < len(suffixBytes) {
		return nil, fmt.Errorf("data too short for suffix (expected at least %d bytes, got %d)", len(suffixBytes), len(data))
	}
	if !bytes.HasSuffix(data, suffixBytes) {
		return nil, fmt.Errorf("data does not have expected suffix")
	}
	return data[:len(data)-len(suffixBytes)], nil
}

