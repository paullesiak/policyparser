package azure

import (
	"github.com/paullesiak/policyparser/pkg/policy"
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

func (a *AzureParser) Json() ([]byte, error) {
	return nil, nil
}

func (a *AzureParser) WriteJson(filename string) error {
	return nil
}
