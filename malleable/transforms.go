package malleable

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// TransformFunction represents a transform function
type TransformFunction struct {
	Name string
	Args []string
}

// TerminationAction defines where transformed data is placed
type TerminationAction struct {
	Type string // "header", "parameter", "uri-append", "print"
	Arg  string // Argument (e.g., "Cookie" for header type)
}

// TransformPipeline represents a complete transform pipeline
type TransformPipeline struct {
	Steps       []TransformFunction
	Termination *TerminationAction
}

// MalleableConfig holds malleable profile configuration
type MalleableConfig struct {
	// HTTP settings
	GetURIs   []string
	PostURIs  []string
	Headers   map[string]string
	
	// Transform pipelines
	GetMetadataTransforms    TransformPipeline
	GetMetadataTransformsFull TransformPipeline
	PostMetadataTransforms   TransformPipeline
	OutputTransforms         TransformPipeline
	
	// Enabled flag
	Enabled bool
}

// ExecutePipeline applies a forward transform pipeline to data
func ExecutePipeline(pipeline TransformPipeline, data []byte) ([]byte, error) {
	result := data
	
	for _, step := range pipeline.Steps {
		var err error
		result, err = ExecuteTransform(step.Name, step.Args, result)
		if err != nil {
			return nil, fmt.Errorf("transform %s failed: %w", step.Name, err)
		}
	}
	
	return result, nil
}

// ReversePipeline applies reverse transforms to extract original data
func ReversePipeline(pipeline TransformPipeline, data []byte) ([]byte, error) {
	result := data
	
	// Reverse order for decoding
	for i := len(pipeline.Steps) - 1; i >= 0; i-- {
		step := pipeline.Steps[i]
		var err error
		result, err = ReverseTransform(step.Name, step.Args, result)
		if err != nil {
			return nil, fmt.Errorf("reverse transform %s failed: %w", step.Name, err)
		}
	}
	
	return result, nil
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
	case "mask":
		if len(args) < 1 {
			return nil, fmt.Errorf("mask requires 1 argument")
		}
		return TransformMask(data, args[0]), nil
	case "netbios":
		return TransformNetBIOS(data), nil
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
		return ReversePrepend(data, args[0]), nil
	case "append":
		if len(args) < 1 {
			return nil, fmt.Errorf("append requires 1 argument")
		}
		return ReverseAppend(data, args[0]), nil
	case "mask":
		if len(args) < 1 {
			return nil, fmt.Errorf("mask requires 1 argument")
		}
		return ReverseMask(data, args[0]), nil
	case "netbios":
		return ReverseNetBIOS(data)
	default:
		return nil, fmt.Errorf("unsupported transform: %s", funcName)
	}
}

// TransformBase64 encodes data as base64
func TransformBase64(data []byte) []byte {
	dst := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(dst, data)
	return dst
}

// ReverseBase64 decodes base64 data
func ReverseBase64(data []byte) ([]byte, error) {
	dst := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
	n, err := base64.StdEncoding.Decode(dst, data)
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}

// TransformBase64URL encodes data as URL-safe base64
func TransformBase64URL(data []byte) []byte {
	dst := make([]byte, base64.URLEncoding.EncodedLen(len(data)))
	base64.URLEncoding.Encode(dst, data)
	return dst
}

// ReverseBase64URL decodes URL-safe base64 data
func ReverseBase64URL(data []byte) ([]byte, error) {
	dst := make([]byte, base64.URLEncoding.DecodedLen(len(data)))
	n, err := base64.URLEncoding.Decode(dst, data)
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}

// TransformPrepend prepends a string to data
func TransformPrepend(data []byte, prefix string) []byte {
	result := make([]byte, len(prefix)+len(data))
	copy(result, []byte(prefix))
	copy(result[len(prefix):], data)
	return result
}

// ReversePrepend removes a prefix from data
func ReversePrepend(data []byte, prefix string) ([]byte, error) {
	if len(data) < len(prefix) {
		return nil, fmt.Errorf("data shorter than prefix")
	}
	if string(data[:len(prefix)]) != prefix {
		return nil, fmt.Errorf("prefix mismatch")
	}
	return data[len(prefix):], nil
}

// TransformAppend appends a string to data
func TransformAppend(data []byte, suffix string) []byte {
	result := make([]byte, len(data)+len(suffix))
	copy(result, data)
	copy(result[len(data):], []byte(suffix))
	return result
}

// ReverseAppend removes a suffix from data
func ReverseAppend(data []byte, suffix string) ([]byte, error) {
	if len(data) < len(suffix) {
		return nil, fmt.Errorf("data shorter than suffix")
	}
	if string(data[len(data)-len(suffix):]) != suffix {
		return nil, fmt.Errorf("suffix mismatch")
	}
	return data[:len(data)-len(suffix)], nil
}

// TransformMask applies XOR mask
func TransformMask(data []byte, maskStr string) []byte {
	mask := []byte(maskStr)
	result := make([]byte, len(data))
	for i := range data {
		result[i] = data[i] ^ mask[i%len(mask)]
	}
	return result
}

// ReverseMask removes XOR mask (same as mask)
func ReverseMask(data []byte, maskStr string) ([]byte, error) {
	return TransformMask(data, maskStr), nil
}

// TransformNetBIOS encodes data using NetBIOS encoding
func TransformNetBIOS(data []byte) []byte {
	result := make([]byte, len(data)*2)
	for i, b := range data {
		high := (b >> 4) & 0x0F
		low := b & 0x0F
		result[i*2] = high + 'A'
		result[i*2+1] = low + 'A'
	}
	return result
}

// ReverseNetBIOS decodes NetBIOS encoded data
func ReverseNetBIOS(data []byte) ([]byte, error) {
	if len(data)%2 != 0 {
		return nil, fmt.Errorf("NetBIOS data length must be even")
	}
	result := make([]byte, len(data)/2)
	for i := 0; i < len(result); i++ {
		high := data[i*2] - 'A'
		low := data[i*2+1] - 'A'
		result[i] = (high << 4) | low
	}
	return result, nil
}

// ExtractTerminationAction extracts termination action from pipeline
func ExtractTerminationAction(pipeline TransformPipeline) *TerminationAction {
	return pipeline.Termination
}

// ApplyTerminationAction applies termination action to place data in request/response
func ApplyTerminationAction(data []byte, action *TerminationAction, req interface{}) error {
	if action == nil {
		return fmt.Errorf("no termination action")
	}
	
	switch action.Type {
	case "header":
		// Place in HTTP header
		// Implementation depends on HTTP request type
		return nil
	case "parameter":
		// Place in POST parameter
		return nil
	case "uri-append":
		// Append to URI
		return nil
	case "print":
		// Place in body
		return nil
	default:
		return fmt.Errorf("unknown termination action: %s", action.Type)
	}
}

