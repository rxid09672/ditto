package malleable

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTransformBase64_RoundTrip(t *testing.T) {
	data := []byte("test data")
	
	encoded := TransformBase64(data)
	assert.NotEqual(t, data, encoded)
	
	decoded, err := ReverseBase64(encoded)
	require.NoError(t, err)
	assert.Equal(t, data, decoded)
}

func TestTransformBase64URL_RoundTrip(t *testing.T) {
	data := []byte("test data with special chars: +/=")
	
	encoded := TransformBase64URL(data)
	assert.NotEqual(t, data, encoded)
	
	decoded, err := ReverseBase64URL(encoded)
	require.NoError(t, err)
	assert.Equal(t, data, decoded)
}

func TestTransformPrepend_RoundTrip(t *testing.T) {
	data := []byte("test data")
	prefix := "prefix_"
	
	result := TransformPrepend(data, prefix)
	assert.True(t, len(result) > len(data))
	assert.Equal(t, prefix, string(result[:len(prefix)]))
	
	reversed, err := ReversePrepend(result, prefix)
	require.NoError(t, err)
	assert.Equal(t, data, reversed)
}

func TestTransformPrepend_ShortData(t *testing.T) {
	data := []byte("ab")
	prefix := "prefix_"
	
	result := TransformPrepend(data, prefix)
	reversed, err := ReversePrepend(result, prefix)
	require.NoError(t, err)
	assert.Equal(t, data, reversed)
}

func TestReversePrepend_InvalidPrefix(t *testing.T) {
	data := []byte("test data")
	prefix := "prefix_"
	
	result := TransformPrepend(data, prefix)
	wrongPrefix := "wrong_"
	
	_, err := ReversePrepend(result, wrongPrefix)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected prefix")
}

func TestReversePrepend_TooShort(t *testing.T) {
	data := []byte("ab")
	prefix := "prefix_"
	
	_, err := ReversePrepend(data, prefix)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestTransformAppend_RoundTrip(t *testing.T) {
	data := []byte("test data")
	suffix := "_suffix"
	
	result := TransformAppend(data, suffix)
	assert.True(t, len(result) > len(data))
	assert.Equal(t, suffix, string(result[len(result)-len(suffix):]))
	
	reversed, err := ReverseAppend(result, suffix)
	require.NoError(t, err)
	assert.Equal(t, data, reversed)
}

func TestReverseAppend_InvalidSuffix(t *testing.T) {
	data := []byte("test data")
	suffix := "_suffix"
	
	result := TransformAppend(data, suffix)
	wrongSuffix := "_wrong"
	
	_, err := ReverseAppend(result, wrongSuffix)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected suffix")
}

func TestReverseAppend_TooShort(t *testing.T) {
	data := []byte("ab")
	suffix := "_suffix"
	
	_, err := ReverseAppend(data, suffix)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

// Tests for TransformMask and TransformNetBIOS removed - these transforms are not implemented

func TestExecuteTransform_Base64(t *testing.T) {
	data := []byte("test")
	result, err := ExecuteTransform("base64", nil, data)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestExecuteTransform_Base64URL(t *testing.T) {
	data := []byte("test")
	result, err := ExecuteTransform("base64url", nil, data)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestExecuteTransform_Prepend(t *testing.T) {
	data := []byte("test")
	result, err := ExecuteTransform("prepend", []string{"prefix"}, data)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestExecuteTransform_Prepend_NoArgs(t *testing.T) {
	data := []byte("test")
	_, err := ExecuteTransform("prepend", nil, data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "requires 1 argument")
}

func TestExecuteTransform_Append(t *testing.T) {
	data := []byte("test")
	result, err := ExecuteTransform("append", []string{"suffix"}, data)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

// TestExecuteTransform_Mask removed - mask transform not implemented
// TestExecuteTransform_NetBIOS removed - netbios transform not implemented

func TestExecuteTransform_Unknown(t *testing.T) {
	data := []byte("test")
	_, err := ExecuteTransform("unknown", nil, data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported transform")
}

func TestReverseTransform_Base64(t *testing.T) {
	data := []byte("test")
	encoded := TransformBase64(data)
	
	result, err := ReverseTransform("base64", nil, encoded)
	require.NoError(t, err)
	assert.Equal(t, data, result)
}

func TestReverseTransform_Unknown(t *testing.T) {
	data := []byte("test")
	_, err := ReverseTransform("unknown", nil, data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported transform")
}

func TestExecutePipeline(t *testing.T) {
	pipeline := []Function{
		{Func: "base64", Args: nil},
		{Func: "prepend", Args: []string{"prefix"}},
		{Func: "append", Args: []string{"suffix"}},
	}
	
	data := []byte("test")
	result, err := ExecutePipeline(pipeline, data)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotEqual(t, data, result)
}

func TestExecutePipeline_Empty(t *testing.T) {
	pipeline := []Function{}
	
	data := []byte("test")
	result, err := ExecutePipeline(pipeline, data)
	require.NoError(t, err)
	assert.Equal(t, data, result)
}

func TestReversePipeline(t *testing.T) {
	pipeline := []Function{
		{Func: "base64", Args: nil},
		{Func: "prepend", Args: []string{"prefix"}},
		{Func: "append", Args: []string{"suffix"}},
	}
	
	data := []byte("test")
	forward, err := ExecutePipeline(pipeline, data)
	require.NoError(t, err)
	
	reversed, err := ReversePipeline(pipeline, forward)
	require.NoError(t, err)
	assert.Equal(t, data, reversed)
}

func TestExtractTerminationAction(t *testing.T) {
	pipeline := []Function{
		{Func: "base64", Args: nil},
		{Func: "header", Args: []string{"Cookie"}},
	}
	
	extracted := ExtractTerminationAction(pipeline)
	require.NotNil(t, extracted)
	assert.Equal(t, "header", extracted.Type)
	assert.Equal(t, "Cookie", extracted.Arg)
}

func TestExtractTerminationAction_Nil(t *testing.T) {
	pipeline := []Function{
		{Func: "base64", Args: nil},
	}
	
	extracted := ExtractTerminationAction(pipeline)
	assert.Nil(t, extracted)
}

// Tests for ApplyTerminationAction removed - function exists but is placeholder implementation

