package gcp

import (
	"github.com/paullesiak/policyparser/pkg/policy"
)

type GcpParser struct {
	policyText string
	urlEscaped bool
}

func NewGcpPolicyParser(policyText string, escaped bool) (*GcpParser, error) {
	return &GcpParser{
		policyText: policyText,
		urlEscaped: escaped,
	}, nil
}

func (a *GcpParser) Parse() error {
	return nil
}

func (a *GcpParser) GetPolicy() ([]*policy.Policy, error) {
	return nil, nil
}

func (a *GcpParser) Json() ([]byte, error) {
	return nil, nil
}

func (a *GcpParser) WriteJson(filename string) error {
	return nil
}
