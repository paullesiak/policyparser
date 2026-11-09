package aws

import (
	"testing"

	"github.com/paullesiak/policyparser/pkg/policy"
	"github.com/stretchr/testify/require"
)

func parsePolicies(t *testing.T, policyText string) []*policy.Policy {
	t.Helper()
	a, err := NewAwsPolicyParser(policyText, false)
	require.NoError(t, err)
	require.NoError(t, a.Parse())
	policies, err := a.GetPolicy()
	require.NoError(t, err)
	return policies
}

// Forms from https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html
func TestAwsParser_GrammarForms(t *testing.T) {
	tests := []struct {
		name       string
		policyText string
		want       []*policy.Policy
	}{
		{
			name: "statement as a single object (AWS managed BedrockAgentCoreRuntimeIdentityServiceRolePolicy)",
			policyText: `{
    "Version": "2012-10-17",
    "Statement": {
        "Sid": "AllowWorkloadIdentityAccess",
        "Effect": "Allow",
        "Action": [
            "bedrock-agentcore:GetWorkloadAccessToken",
            "bedrock-agentcore:GetWorkloadAccessTokenForJWT",
            "bedrock-agentcore:GetWorkloadAccessTokenForUserId"
        ],
        "Resource": [
            "arn:aws:bedrock-agentcore:*:*:workload-identity-directory/default",
            "arn:aws:bedrock-agentcore:*:*:workload-identity-directory/default/workload-identity/*"
        ]
    }
}`,
			want: []*policy.Policy{{
				Id:      "AllowWorkloadIdentityAccess",
				Version: "2012-10-17",
				Actions: []string{
					"bedrock-agentcore:GetWorkloadAccessToken",
					"bedrock-agentcore:GetWorkloadAccessTokenForJWT",
					"bedrock-agentcore:GetWorkloadAccessTokenForUserId",
				},
				Resources: []string{
					"arn:aws:bedrock-agentcore:<.*>:<.*>:workload-identity-directory/default",
					"arn:aws:bedrock-agentcore:<.*>:<.*>:workload-identity-directory/default/workload-identity/<.*>",
				},
				Allowed: true,
			}},
		},
		{
			name:       "version 2008-10-17 with id, star action and single string resource",
			policyText: `{"Version": "2008-10-17", "Id": "Admin_Policy", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::amzn-s3-demo-bucket/*"}]}`,
			want: []*policy.Policy{{
				Id: "Admin_Policy:0", Version: "2008-10-17",
				Actions: []string{"<.*>"}, Resources: []string{"arn:aws:s3:::amzn-s3-demo-bucket/<.*>"}, Allowed: true,
			}},
		},
		{
			name:       "deny with not action and not resource",
			policyText: `{"Version": "2012-10-17", "Statement": [{"Sid": "DenyOutside", "Effect": "Deny", "NotAction": ["s3:Get*", "s3:List*"], "NotResource": "arn:aws:s3:::allowed-bucket"}]}`,
			want: []*policy.Policy{{
				Id: "DenyOutside", Version: "2012-10-17",
				NotActions: []string{"s3:Get<.*>", "s3:List<.*>"}, NotResources: []string{"arn:aws:s3:::allowed-bucket"},
			}},
		},
		{
			name:       "principal wildcard",
			policyText: `{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "*"}]}`,
			want: []*policy.Policy{{
				Id: ":0", Version: "2012-10-17",
				Subjects: []string{"<.*>"}, Actions: []string{"s3:GetObject"}, Resources: []string{"<.*>"}, Allowed: true,
			}},
		},
		{
			name: "principal map with every entry type as arrays and single strings",
			policyText: `{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {
    "AWS": ["arn:aws:iam::123456789012:root", "arn:aws:iam::123456789012:user/Bob"],
    "Federated": "cognito-identity.amazonaws.com",
    "Service": "ec2.amazonaws.com",
    "CanonicalUser": "79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be"
}, "Action": "sts:AssumeRole", "Resource": "*"}]}`,
			want: []*policy.Policy{{
				Id: ":0", Version: "2012-10-17",
				Subjects: []string{
					"arn:aws:iam::123456789012:root",
					"arn:aws:iam::123456789012:user/Bob",
					"cognito-identity.amazonaws.com",
					"ec2.amazonaws.com",
					"79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be",
				},
				Actions: []string{"sts:AssumeRole"}, Resources: []string{"<.*>"}, Allowed: true,
			}},
		},
		{
			name:       "not principal",
			policyText: `{"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "NotPrincipal": {"AWS": "arn:aws:iam::123456789012:user/Bob"}, "Action": "s3:*", "Resource": "arn:aws:s3:::amzn-s3-demo-bucket"}]}`,
			want: []*policy.Policy{{
				Id: ":0", Version: "2012-10-17",
				NotSubjects: []string{"arn:aws:iam::123456789012:user/Bob"}, Actions: []string{"s3:<.*>"}, Resources: []string{"arn:aws:s3:::amzn-s3-demo-bucket"},
			}},
		},
		{
			name: "condition operators with strings, quoted and unquoted numbers, booleans, lists, set operator and IfExists",
			policyText: `{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "arn:aws:s3:::amzn-s3-demo-bucket", "Condition": {
    "StringEquals": {"aws:PrincipalTag/team": "data", "aws:RequestedRegion": ["us-west-2", "us-east-1"]},
    "NumericLessThanEquals": {"s3:max-keys": "10"},
    "NumericLessThan": {"s3:max-keys": 10},
    "Bool": {"aws:SecureTransport": true},
    "ForAnyValue:StringLike": {"dynamodb:Attributes": ["ID", "PostDateTime"]},
    "StringEqualsIfExists": {"aws:ResourceTag/env": "prod"},
    "Null": {"aws:TokenIssueTime": "true"}
}}]}`,
			want: []*policy.Policy{{
				Id: ":0", Version: "2012-10-17",
				Actions: []string{"s3:ListBucket"}, Resources: []string{"arn:aws:s3:::amzn-s3-demo-bucket"}, Allowed: true,
				Condition: []policy.Condition{
					{Operation: "StringEquals", Key: []string{"aws:PrincipalTag/team", "aws:RequestedRegion"}, Value: []any{[]string{"data"}, []string{"us-west-2", "us-east-1"}}, Type: []string{"string", "string"}},
					{Operation: "NumericLessThanEquals", Key: []string{"s3:max-keys"}, Value: []any{[]string{"10"}}, Type: []string{"string"}},
					{Operation: "NumericLessThan", Key: []string{"s3:max-keys"}, Value: []any{[]int64{10}}, Type: []string{"int64"}},
					{Operation: "Bool", Key: []string{"aws:SecureTransport"}, Value: []any{[]bool{true}}, Type: []string{"bool"}},
					{Operation: "ForAnyValue:StringLike", Key: []string{"dynamodb:Attributes"}, Value: []any{[]string{"ID", "PostDateTime"}}, Type: []string{"string"}},
					{Operation: "StringEqualsIfExists", Key: []string{"aws:ResourceTag/env"}, Value: []any{[]string{"prod"}}, Type: []string{"string"}},
					{Operation: "Null", Key: []string{"aws:TokenIssueTime"}, Value: []any{[]string{"true"}}, Type: []string{"string"}},
				},
			}},
		},
		{
			name: "numeric condition values as lists, negatives, decimals and exponents",
			policyText: `{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*", "Condition": {
    "NumericEquals": {"s3:max-keys": [1, 2]},
    "NumericLessThan": {"s3:max-keys": -5},
    "NumericGreaterThan": {"aws:MultiFactorAuthAge": 2.5},
    "NumericGreaterThanEquals": {"aws:MultiFactorAuthAge": [-0.5, 1e3]}
}}]}`,
			want: []*policy.Policy{{
				Id: ":0", Version: "2012-10-17",
				Actions: []string{"s3:ListBucket"}, Resources: []string{"<.*>"}, Allowed: true,
				Condition: []policy.Condition{
					{Operation: "NumericEquals", Key: []string{"s3:max-keys"}, Value: []any{[]int64{1, 2}}, Type: []string{"int64"}},
					{Operation: "NumericLessThan", Key: []string{"s3:max-keys"}, Value: []any{[]int64{-5}}, Type: []string{"int64"}},
					{Operation: "NumericGreaterThan", Key: []string{"aws:MultiFactorAuthAge"}, Value: []any{[]float64{2.5}}, Type: []string{"float64"}},
					{Operation: "NumericGreaterThanEquals", Key: []string{"aws:MultiFactorAuthAge"}, Value: []any{[]float64{-0.5, 1000}}, Type: []string{"float64"}},
				},
			}},
		},
		{
			name:       "blocks in any order at policy and statement level",
			policyText: `{"Statement": [{"Condition": {"Bool": {"aws:SecureTransport": "false"}}, "Resource": "*", "Action": "s3:GetObject", "Effect": "Deny", "Sid": "OrderDoesNotMatter"}], "Id": "ordered", "Version": "2012-10-17"}`,
			want: []*policy.Policy{{
				Id: "OrderDoesNotMatter", Version: "2012-10-17",
				Actions: []string{"s3:GetObject"}, Resources: []string{"<.*>"},
				Condition: []policy.Condition{{Operation: "Bool", Key: []string{"aws:SecureTransport"}, Value: []any{[]string{"false"}}, Type: []string{"string"}}},
			}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, parsePolicies(t, tt.policyText))
		})
	}
}

func TestAwsParser_EquivalentForms(t *testing.T) {
	tests := []struct {
		name      string
		canonical string
		variant   string
	}{
		{
			name:      "statement array versus single statement object",
			canonical: `{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}`,
			variant:   `{"Version": "2012-10-17", "Statement": {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}}`,
		},
		{
			name:      "single element action array versus string",
			canonical: `{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}]}`,
			variant:   `{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}`,
		},
		{
			name:      "single element resource array versus string",
			canonical: `{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": ["arn:aws:s3:::b/*"]}]}`,
			variant:   `{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}]}`,
		},
		{
			name:      "single element principal array versus string",
			canonical: `{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": ["arn:aws:iam::123456789012:root"]}, "Action": "s3:GetObject", "Resource": "*"}]}`,
			variant:   `{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:root"}, "Action": "s3:GetObject", "Resource": "*"}]}`,
		},
		{
			name:      "single element condition value list versus value",
			canonical: `{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*", "Condition": {"StringEquals": {"aws:username": ["bob"]}}}]}`,
			variant:   `{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*", "Condition": {"StringEquals": {"aws:username": "bob"}}}]}`,
		},
		{
			name:      "policy blocks reordered",
			canonical: `{"Version": "2012-10-17", "Id": "p", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}`,
			variant:   `{"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}], "Id": "p", "Version": "2012-10-17"}`,
		},
		{
			name:      "statement elements reordered",
			canonical: `{"Version": "2012-10-17", "Statement": [{"Sid": "s", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*", "Condition": {"Bool": {"aws:SecureTransport": "true"}}}]}`,
			variant:   `{"Version": "2012-10-17", "Statement": [{"Condition": {"Bool": {"aws:SecureTransport": "true"}}, "Resource": "*", "Action": "s3:GetObject", "Effect": "Allow", "Sid": "s"}]}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, parsePolicies(t, tt.canonical), parsePolicies(t, tt.variant))
		})
	}
}

func TestAwsParser_RejectsMisplacedBlocks(t *testing.T) {
	tests := []struct {
		name       string
		policyText string
		wantErr    error
	}{
		{name: "no statement block", policyText: `{"Version": "2012-10-17"}`, wantErr: ErrNoStatements},
		{name: "statement is a string", policyText: `{"Statement": "allow everything"}`, wantErr: ErrStatementNotBlock},
		{name: "version is a statement object", policyText: `{"Version": {"Effect": "Allow"}, "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}`, wantErr: ErrPropertyNotString},
		{name: "id is a statement object", policyText: `{"Id": {"Condition": {"Bool": {"aws:SecureTransport": true}}}, "Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}}`, wantErr: ErrPropertyNotString},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := NewAwsPolicyParser(tt.policyText, false)
			require.NoError(t, err)
			require.ErrorIs(t, a.Parse(), tt.wantErr)
		})
	}
}
