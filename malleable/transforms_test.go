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
	assert.Contains(t, err.Error(), "prefix mismatch")
}

func TestReversePrepend_TooShort(t *testing.T) {
	data := []byte("ab")
	prefix := "prefix_"
	
	_, err := ReversePrepend(data, prefix)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "shorter than prefix")
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
	assert.Contains(t, err.Error(), "suffix mismatch")
}

func TestReverseAppend_TooShort(t *testing.T) {
	data := []byte("ab")
	suffix := "_suffix"
	
	_, err := ReverseAppend(data, suffix)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "shorter than suffix")
}

func TestTransformMask_RoundTrip(t *testing.T) {
	data := []byte("test data")
	mask := "key"
	
	masked := TransformMask(data, mask)
	assert.NotEqual(t, data, masked)
	
	unmasked, err := ReverseMask(masked, mask)
	require.NoError(t, err)
	assert.Equal(t, data, unmasked)
}

func TestTransformMask_LongData(t *testing.T) {
	data := make([]byte, 1000)
	for i := range data {
		data[i] = byte(i % 256)
	}
	mask := "short"
	
	masked := TransformMask(data, mask)
	unmasked, err := ReverseMask(masked, mask)
	require.NoError(t, err)
	assert.Equal(t, data, unmasked)
}

func TestTransformMask_EmptyMask(t *testing.T) {
	data := []byte("test data")
	mask := ""
	
	result := TransformMask(data, mask)
	assert.Equal(t, data, result)
}

func TestTransformNetBIOS_RoundTrip(t *testing.T) {
	data := []byte{0x12, 0x34, 0x56, 0x78}
	
	encoded := TransformNetBIOS(data)
	assert.Len(t, encoded, len(data)*2)
	
	decoded, err := ReverseNetBIOS(encoded)
	require.NoError(t, err)
	assert.Equal(t, data, decoded)
}

func TestReverseNetBIOS_OddLength(t *testing.T) {
	data := []byte{0x12, 0x34, 0x56} // Odd length
	
	_, err := ReverseNetBIOS(data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must be even")
}

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

func TestExecuteTransform_Mask(t *testing.T) {
	data := []byte("test")
	result, err := ExecuteTransform("mask", []string{"key"}, data)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestExecuteTransform_NetBIOS(t *testing.T) {
	data := []byte("test")
	result, err := ExecuteTransform("netbios", nil, data)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

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
	pipeline := TransformPipeline{
		Steps: []TransformFunction{
			{Name: "base64", Args: nil},
			{Name: "prepend", Args: []string{"prefix"}},
			{Name: "append", Args: []string{"suffix"}},
		},
	}
	
	data := []byte("test")
	result, err := ExecutePipeline(pipeline, data)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotEqual(t, data, result)
}

func TestExecutePipeline_Empty(t *testing.T) {
	pipeline := TransformPipeline{
		Steps: []TransformFunction{},
	}
	
	data := []byte("test")
	result, err := ExecutePipeline(pipeline, data)
	require.NoError(t, err)
	assert.Equal(t, data, result)
}

func TestReversePipeline(t *testing.T) {
	pipeline := TransformPipeline{
		Steps: []TransformFunction{
			{Name: "base64", Args: nil},
			{Name: "prepend", Args: []string{"prefix"}},
			{Name: "append", Args: []string{"suffix"}},
		},
	}
	
	data := []byte("test")
	forward, err := ExecutePipeline(pipeline, data)
	require.NoError(t, err)
	
	reversed, err := ReversePipeline(pipeline, forward)
	require.NoError(t, err)
	assert.Equal(t, data, reversed)
}

func TestExtractTerminationAction(t *testing.T) {
	action := &TerminationAction{
		Type: "header",
		Arg:  "Cookie",
	}
	pipeline := TransformPipeline{
		Termination: action,
	}
	
	extracted := ExtractTerminationAction(pipeline)
	assert.Equal(t, action, extracted)
}

func TestExtractTerminationAction_Nil(t *testing.T) {
	pipeline := TransformPipeline{
		Termination: nil,
	}
	
	extracted := ExtractTerminationAction(pipeline)
	assert.Nil(t, extracted)
}

func TestApplyTerminationAction_Nil(t *testing.T) {
	err := ApplyTerminationAction([]byte("test"), nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no termination action")
}

func TestApplyTerminationAction_Header(t *testing.T) {
	action := &TerminationAction{
		Type: "header",
		Arg:  "Cookie",
	}
	err := ApplyTerminationAction([]byte("test"), action, nil)
	assert.NoError(t, err)
}

func TestApplyTerminationAction_Parameter(t *testing.T) {
	action := &TerminationAction{
		Type: "parameter",
		Arg:  "data",
	}
	err := ApplyTerminationAction([]byte("test"), action, nil)
	assert.NoError(t, err)
}

func TestApplyTerminationAction_URIAppend(t *testing.T) {
	action := &TerminationAction{
		Type: "uri-append",
	}
	err := ApplyTerminationAction([]byte("test"), action, nil)
	assert.NoError(t, err)
}

func TestApplyTerminationAction_Print(t *testing.T) {
	action := &TerminationAction{
		Type: "print",
	}
	err := ApplyTerminationAction([]byte("test"), action, nil)
	assert.NoError(t, err)
}

func TestApplyTerminationAction_Unknown(t *testing.T) {
	action := &TerminationAction{
		Type: "unknown",
	}
	err := ApplyTerminationAction([]byte("test"), action, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown termination action")
}

func TestPipeline_Complex(t *testing.T) {
	pipeline := TransformPipeline{
		Steps: []TransformFunction{
			{Name: "base64", Args: nil},
			{Name: "mask", Args: []string{"secret"}},
			{Name: "prepend", Args: []string{"A"}},
			{Name: "append", Args: []string{"B"}},
			{Name: "netbios", Args: nil},
		},
	}
	
	data := []byte("complex test data")
	forward, err := ExecutePipeline(pipeline, data)
	require.NoError(t, err)
	
	reversed, err := ReversePipeline(pipeline, forward)
	require.NoError(t, err)
	assert.Equal(t, data, reversed)
}

