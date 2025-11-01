package bof

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"

	"golang.org/x/text/encoding/unicode"
)

// PackArguments packs BOF arguments according to format string
// Format string characters:
//   - 'b': Binary data (4-byte length + data)
//   - 'i': 4-byte signed integer
//   - 's': 2-byte signed short integer
//   - 'z': Zero-terminated UTF-8 string (4-byte length + string + null terminator)
//   - 'Z': Zero-terminated UTF-16 wide string (4-byte length + UTF-16LE string + null terminator)
func PackArguments(formatString string, args []string) ([]byte, error) {
	if len(formatString) != len(args) {
		return nil, fmt.Errorf("format string length (%d) must match arguments length (%d)", len(formatString), len(args))
	}

	buffer := new(bytes.Buffer)

	// Pack each argument according to format string
	for i, c := range formatString {
		arg := args[i]

		switch c {
		case 'b':
			// Binary data - read from file path or treat as hex/base64
			data, err := parseBinaryData(arg)
			if err != nil {
				return nil, fmt.Errorf("invalid binary data at position %d: %w", i, err)
			}
			if err := addBinary(buffer, data); err != nil {
				return nil, fmt.Errorf("failed to pack binary data at position %d: %w", i, err)
			}

		case 'i':
			// 4-byte signed integer
			var val int32
			if _, err := fmt.Sscanf(arg, "%d", &val); err != nil {
				return nil, fmt.Errorf("invalid integer at position %d: %w", i, err)
			}
			if err := binary.Write(buffer, binary.LittleEndian, val); err != nil {
				return nil, fmt.Errorf("failed to pack integer at position %d: %w", i, err)
			}

		case 's':
			// 2-byte signed short
			var val int16
			if _, err := fmt.Sscanf(arg, "%d", &val); err != nil {
				return nil, fmt.Errorf("invalid short at position %d: %w", i, err)
			}
			if err := binary.Write(buffer, binary.LittleEndian, val); err != nil {
				return nil, fmt.Errorf("failed to pack short at position %d: %w", i, err)
			}

		case 'z':
			// Zero-terminated UTF-8 string
			if err := addString(buffer, arg); err != nil {
				return nil, fmt.Errorf("failed to pack string at position %d: %w", i, err)
			}

		case 'Z':
			// Zero-terminated UTF-16 wide string
			if err := addWString(buffer, arg); err != nil {
				return nil, fmt.Errorf("failed to pack wide string at position %d: %w", i, err)
			}

		default:
			return nil, fmt.Errorf("invalid format character '%c' at position %d", c, i)
		}
	}

	// Prepend buffer length (4 bytes)
	finalBuffer := new(bytes.Buffer)
	if err := binary.Write(finalBuffer, binary.LittleEndian, uint32(buffer.Len())); err != nil {
		return nil, fmt.Errorf("failed to write buffer length: %w", err)
	}
	if _, err := finalBuffer.Write(buffer.Bytes()); err != nil {
		return nil, fmt.Errorf("failed to write buffer: %w", err)
	}

	return finalBuffer.Bytes(), nil
}

// addBinary adds binary data with length prefix
func addBinary(buffer *bytes.Buffer, data []byte) error {
	dataLen := uint32(len(data))
	if err := binary.Write(buffer, binary.LittleEndian, dataLen); err != nil {
		return err
	}
	if _, err := buffer.Write(data); err != nil {
		return err
	}
	return nil
}

// addString adds UTF-8 string with length prefix and null terminator
func addString(buffer *bytes.Buffer, s string) error {
	strBytes := []byte(s)
	// Add null terminator
	strBytes = append(strBytes, 0x00)
	strLen := uint32(len(strBytes))
	if err := binary.Write(buffer, binary.LittleEndian, strLen); err != nil {
		return err
	}
	if _, err := buffer.Write(strBytes); err != nil {
		return err
	}
	return nil
}

// addWString adds UTF-16LE wide string with length prefix and null terminator
func addWString(buffer *bytes.Buffer, s string) error {
	// Convert to UTF-16LE
	utf16Encoder := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder()
	utf16Bytes, err := utf16Encoder.Bytes([]byte(s))
	if err != nil {
		return err
	}
	// Add null terminator (2 bytes for UTF-16)
	utf16Bytes = append(utf16Bytes, 0x00, 0x00)
	strLen := uint32(len(utf16Bytes))
	if err := binary.Write(buffer, binary.LittleEndian, strLen); err != nil {
		return err
	}
	if _, err := buffer.Write(utf16Bytes); err != nil {
		return err
	}
	return nil
}

// parseBinaryData attempts to parse binary data from various formats
// Supports: file paths (file:/path), hex strings, base64 strings
func parseBinaryData(arg string) ([]byte, error) {
	// Check if it's a file path
	if len(arg) > 6 && arg[:6] == "file:/" {
		return nil, fmt.Errorf("file paths not yet supported, use hex or base64")
	}

	// Try hex decoding first
	if data, err := hexDecode(arg); err == nil {
		return data, nil
	}

	// Try base64 decoding
	if data, err := base64Decode(arg); err == nil {
		return data, nil
	}

	return nil, fmt.Errorf("unable to parse binary data, expected hex or base64")
}

// hexDecode attempts to decode hex string
func hexDecode(s string) ([]byte, error) {
	// Remove common hex prefixes
	sBytes := []byte(s)
	sBytes = bytes.TrimPrefix(bytes.TrimPrefix(sBytes, []byte("0x")), []byte("0X"))
	sBytes = bytes.TrimPrefix(sBytes, []byte("\\x"))
	s = string(sBytes)
	
	// Try to decode
	var result []byte
	for i := 0; i < len(s); i += 2 {
		if i+1 >= len(s) {
			return nil, fmt.Errorf("invalid hex string length")
		}
		var b byte
		if _, err := fmt.Sscanf(string(s[i:i+2]), "%02x", &b); err != nil {
			return nil, err
		}
		result = append(result, b)
	}
	return result, nil
}

// base64Decode attempts to decode base64 string
func base64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

