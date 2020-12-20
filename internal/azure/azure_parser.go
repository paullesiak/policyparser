package azure

import (
	"github.com/aumahesh/policyparser/pkg/policy"
)

type AzureParser struct {
	policyText string
	urlEscaped bool
}

func NewAzurePolicyParser(policyText string, escaped bool) (*AzureParser, error) {
	return &AzureParser{
		policyText: policyText,
		urlEscaped: escaped,
	}, nil
}

func (a *AzureParser) Parse() error {
	return nil
}

func (a *AzureParser) GetPolicy() ([]*policy.Policy, error) {
	return nil, nil
}
