package parser

import (
	"fmt"

	"github.com/paullesiak/policyparser/internal/aws"
	"github.com/paullesiak/policyparser/internal/azure"
	"github.com/paullesiak/policyparser/internal/gcp"
	"github.com/paullesiak/policyparser/pkg/policy"
)

const (
	Aws   = "aws"
	Azure = "azure"
	Gcp   = "gcp"
)

type Parser interface {
	Parse() error
	GetPolicy() ([]*policy.Policy, error)
	Json() ([]byte, error)
	WriteJson(string) error
}

func NewParser(p, policyText string, escaped bool) (Parser, error) {
	switch p {
	case Aws:
		return aws.NewAwsPolicyParser(policyText, escaped)
	case Azure:
		return azure.NewAzurePolicyParser(policyText, escaped)
	case Gcp:
		return gcp.NewGcpPolicyParser(policyText, escaped)
	}
	return nil, fmt.Errorf("%s is not a supported cloud provider", p)
}
