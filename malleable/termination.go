package malleable

/*
	Malleable C2 Termination Actions
	Handles extraction and placement of transformed data based on termination actions
*/

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// TerminationAction defines where transformed data is placed
type TerminationAction struct {
	Type string // "header", "parameter", "uri-append", "print"
	Arg  string // Argument (e.g., "Cookie" for header type)
}

// ExtractFromRequest extracts data from an HTTP request based on termination action
func ExtractFromRequest(req *http.Request, action *TerminationAction) ([]byte, error) {
	if action == nil {
		// Default: extract from body
		return nil, fmt.Errorf("no termination action specified")
	}

	switch action.Type {
	case "header":
		if action.Arg == "" {
			return nil, fmt.Errorf("header termination action requires header name")
		}
		value := req.Header.Get(action.Arg)
		return []byte(value), nil

	case "parameter":
		if action.Arg == "" {
			return nil, fmt.Errorf("parameter termination action requires parameter name")
		}
		value := req.URL.Query().Get(action.Arg)
		return []byte(value), nil

	case "uri-append":
		// Extract data appended to URI path
		// For URI-append, the data is typically at the end of the path after the base path
		// Base paths are typically: /beacon, /task, /result, /module/, /upgrade
		path := req.URL.Path
		
		// Extract appended portion after common base paths
		basePaths := []string{"/beacon", "/task", "/result", "/module/", "/upgrade"}
		for _, basePath := range basePaths {
			if strings.HasPrefix(path, basePath) {
				appended := strings.TrimPrefix(path, basePath)
				if appended != "" {
					return []byte(appended), nil
				}
			}
		}
		
		// If no base path matched, return entire path (fallback behavior)
		// Full implementation would require profile context to know exact base path
		return []byte(path), nil

	case "print":
		// Extract from request body
		if req.Body == nil {
			return nil, nil
		}
		// Use io.ReadAll to read entire body, handling chunked transfers
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read body: %w", err)
		}
		return body, nil

	default:
		return nil, fmt.Errorf("unknown termination action: %s", action.Type)
	}
}

// ApplyToRequest applies transformed data to an HTTP request based on termination action
func ApplyToRequest(req *http.Request, data []byte, action *TerminationAction) error {
	if action == nil {
		return fmt.Errorf("no termination action specified")
	}

	switch action.Type {
	case "header":
		if action.Arg == "" {
			return fmt.Errorf("header termination action requires header name")
		}
		req.Header.Set(action.Arg, string(data))
		return nil

	case "parameter":
		if action.Arg == "" {
			return fmt.Errorf("parameter termination action requires parameter name")
		}
		query := req.URL.Query()
		query.Set(action.Arg, string(data))
		req.URL.RawQuery = query.Encode()
		return nil

	case "uri-append":
		// Append data to URI path
		req.URL.Path = req.URL.Path + string(data)
		return nil

	case "print":
		// Place in request body
		// Note: This modifies the request body - caller should handle properly
		req.Body = http.NoBody // Clear existing body
		req.ContentLength = int64(len(data))
		req.Body = &bodyReader{data: data}
		return nil

	default:
		return fmt.Errorf("unknown termination action: %s", action.Type)
	}
}

// ApplyToResponse applies transformed data to an HTTP response based on termination action
func ApplyToResponse(resp http.ResponseWriter, data []byte, action *TerminationAction) error {
	if action == nil {
		// Default: write to body
		_, err := resp.Write(data)
		return err
	}

	switch action.Type {
	case "header":
		if action.Arg == "" {
			return fmt.Errorf("header termination action requires header name")
		}
		resp.Header().Set(action.Arg, string(data))
		// Also write to body for termination actions that might need both
		_, err := resp.Write(data)
		return err

	case "parameter":
		// Parameters don't make sense for responses
		// Fall through to print
		fallthrough

	case "uri-append":
		// URI-append doesn't make sense for responses
		// Fall through to print
		fallthrough

	case "print":
		// Write to response body
		_, err := resp.Write(data)
		return err

	default:
		// Default: write to body
		_, err := resp.Write(data)
		return err
	}
}

// ExtractFromURI extracts data from URI path (for uri-append termination)
func ExtractFromURI(uri string, baseURI string) ([]byte, error) {
	if !strings.HasPrefix(uri, baseURI) {
		return nil, fmt.Errorf("URI does not match base URI")
	}

	// Extract the appended portion
	appended := strings.TrimPrefix(uri, baseURI)
	return []byte(appended), nil
}

// bodyReader is a simple reader for request body
type bodyReader struct {
	data []byte
	pos  int
}

func (br *bodyReader) Read(p []byte) (n int, err error) {
	if br.pos >= len(br.data) {
		return 0, io.EOF
	}
	n = copy(p, br.data[br.pos:])
	br.pos += n
	if br.pos >= len(br.data) {
		err = io.EOF
	}
	return n, err
}

// Close implements io.Closer
func (br *bodyReader) Close() error {
	br.pos = len(br.data)
	return nil
}

// ParseURIAppend extracts data appended to URI after base path
func ParseURIAppend(fullPath string, basePath string) (string, error) {
	if !strings.HasPrefix(fullPath, basePath) {
		return "", fmt.Errorf("path does not start with base path")
	}

	appended := strings.TrimPrefix(fullPath, basePath)
	return appended, nil
}

// BuildParameterURL builds a URL with a parameter containing the data
func BuildParameterURL(baseURL string, paramName string, data string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("invalid base URL: %w", err)
	}

	q := u.Query()
	q.Set(paramName, data)
	u.RawQuery = q.Encode()

	return u.String(), nil
}

