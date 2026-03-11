package parser

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewParser(t *testing.T) {
	tests := []struct {
		name        string
		provider    string
		policyText  string
		escaped     bool
		expectError bool
		errorMsg    string
	}{
		{
			name:        "AWS Parser",
			provider:    Aws,
			policyText:  "{}",
			escaped:     false,
			expectError: false,
		},
		{
			name:        "Azure Parser",
			provider:    Azure,
			policyText:  "{}",
			escaped:     false,
			expectError: false,
		},
		{
			name:        "GCP Parser",
			provider:    Gcp,
			policyText:  "{}",
			escaped:     false,
			expectError: false,
		},
		{
			name:        "Unsupported Provider",
			provider:    "invalid",
			policyText:  "{}",
			escaped:     false,
			expectError: true,
			errorMsg:    "invalid is not a supported cloud provider",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser, err := NewParser(tt.provider, tt.policyText, tt.escaped)

			if tt.expectError {
				require.Error(t, err)
				require.Nil(t, parser)
				require.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)
				require.NotNil(t, parser)
			}
		})
	}
}
