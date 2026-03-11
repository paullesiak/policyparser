package gcp

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewGcpPolicyParser(t *testing.T) {
	testPolicy := "{}"
	parser, err := NewGcpPolicyParser(testPolicy, false)

	require.NoError(t, err)
	require.NotNil(t, parser)
	require.Equal(t, testPolicy, parser.policyText)
	require.False(t, parser.urlEscaped)

	parserEscaped, errEscaped := NewGcpPolicyParser(testPolicy, true)
	require.NoError(t, errEscaped)
	require.NotNil(t, parserEscaped)
	require.True(t, parserEscaped.urlEscaped)
}
