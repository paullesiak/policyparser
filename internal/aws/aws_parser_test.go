package aws

import (
	"errors"
	"os"
	"testing"

	"fmt"
	"strings"

	"github.com/alecthomas/participle/v2"
	"github.com/alecthomas/participle/v2/lexer"
	log "github.com/paullesiak/policyparser/internal/logger"
	"github.com/paullesiak/policyparser/pkg/policy"
	"github.com/stretchr/testify/require"
)

// TestAwsParse is the template test function, that all other tests in this package should be included into
func TestAwsParse(t *testing.T) {
	defer log.SetLevel(log.CurrentLevel())
	log.SetLevel(log.DebugLevel)
	type testCase struct {
		name              string
		escaped           bool
		policyText        string
		verificationLogic func(t *testing.T, a *AwsParser)
	}
	tests := []testCase{
		{
			name: "parse1",
			policyText: `{
						"Version": "2012-10-17",
						"Statement": [
							{
								"Effect": "Deny",
								"Action": "iam:CreateUser",
								"Resource": "*"
							},
							{
								"Effect": "Allow",
								"Action": ["*"],
								"Resource": "*"
							}
						]
						}`,
			escaped: false,
			verificationLogic: func(t *testing.T, a *AwsParser) {
				policies, err := a.GetPolicy()
				require.NoError(t, err)
				require.Len(t, policies, 2)
				require.False(t, policies[0].Allowed)
				require.Len(t, policies[0].Subjects, 0)
				require.Len(t, policies[0].NotSubjects, 0)
				require.Len(t, policies[0].NotActions, 0)
				require.Len(t, policies[0].NotResources, 0)
				require.Len(t, policies[0].Actions, 1)
				require.EqualValues(t, "iam:CreateUser", policies[0].Actions[0])
				require.Len(t, policies[0].Resources, 1)
				require.EqualValues(t, "<.*>", policies[0].Resources[0])
				require.True(t, policies[1].Allowed)
				require.Len(t, policies[1].Subjects, 0)
				require.Len(t, policies[1].NotSubjects, 0)
				require.Len(t, policies[1].NotActions, 0)
				require.Len(t, policies[1].NotResources, 0)
				require.Len(t, policies[1].Actions, 1)
				require.EqualValues(t, "<.*>", policies[1].Actions[0])
				require.Len(t, policies[1].Resources, 1)
				require.EqualValues(t, "<.*>", policies[1].Resources[0])
			},
		},
		{
			name: "parse2",
			policyText: `{
						  "Version": "2012-10-17",
						  "Statement": [
							{
							  "Effect": "Allow",
							  "Action": ["iam:CreateUser", "iam:RemoveUser"],
							  "Resource": "*"
							}
						  ]
						}`,
			escaped: false,
			verificationLogic: func(t *testing.T, a *AwsParser) {
				policies, err := a.GetPolicy()
				require.NoError(t, err)
				require.Len(t, policies, 1)
				require.True(t, policies[0].Allowed)
				require.Len(t, policies[0].Subjects, 0)
				require.Len(t, policies[0].NotSubjects, 0)
				require.Len(t, policies[0].NotActions, 0)
				require.Len(t, policies[0].NotResources, 0)
				require.Len(t, policies[0].Actions, 2)
				require.EqualValues(t, "iam:CreateUser", policies[0].Actions[0])
				require.EqualValues(t, "iam:RemoveUser", policies[0].Actions[1])
				require.Len(t, policies[0].Resources, 1)
				require.EqualValues(t, "<.*>", policies[0].Resources[0])
			},
		},
		{
			name: "parse3",
			policyText: `{
						  "Version": "2012-10-17",
						  "Statement": [
							{
							  "Sid": "IAMRoleProvisioningActions",
							  "Effect": "Allow",
							  "Action": [
								"iam:AttachRolePolicy",
								"iam:CreateRole",
								"iam:PutRolePolicy",
								"iam:UpdateRole",
								"iam:UpdateRoleDescription",
								"iam:UpdateAssumeRolePolicy"
							  ],
							  "Resource": [
								"arn:aws:iam::*:role/aws-reserved/sso.amazonaws.com/*"
							  ],
							  "Condition": {
								"StringNotEquals": {
								  "aws:PrincipalOrgMasterAccountId": "${aws:PrincipalAccount}"
								}
							  }
							}
						  ]
						}`,
			escaped: false,
			verificationLogic: func(t *testing.T, a *AwsParser) {
				policies, err := a.GetPolicy()
				require.NoError(t, err)
				require.Len(t, policies, 1)
				require.True(t, policies[0].Allowed)
				require.Len(t, policies[0].Subjects, 0)
				require.Len(t, policies[0].NotSubjects, 0)
				require.Len(t, policies[0].NotActions, 0)
				require.Len(t, policies[0].NotResources, 0)
				require.Len(t, policies[0].Actions, 6)
				require.EqualValues(t, "iam:AttachRolePolicy", policies[0].Actions[0])
				require.EqualValues(t, "iam:CreateRole", policies[0].Actions[1])
				require.EqualValues(t, "iam:PutRolePolicy", policies[0].Actions[2])
				require.EqualValues(t, "iam:UpdateRole", policies[0].Actions[3])
				require.EqualValues(t, "iam:UpdateRoleDescription", policies[0].Actions[4])
				require.EqualValues(t, "iam:UpdateAssumeRolePolicy", policies[0].Actions[5])
				require.Len(t, policies[0].Resources, 1)
				require.EqualValues(
					t,
					"arn:aws:iam::<.*>:role/aws-reserved/sso.amazonaws.com/<.*>",
					policies[0].Resources[0],
				)
				require.Len(t, policies[0].Condition, 1)
				require.EqualValues(t, "StringNotEquals", policies[0].Condition[0].Operation)
				require.EqualValues(t, "aws:PrincipalOrgMasterAccountId", policies[0].Condition[0].Key[0])
				require.Len(t, policies[0].Condition[0].Value, 1)
				require.EqualValues(t, "string", policies[0].Condition[0].Type[0])
				vs := policies[0].Condition[0].Value[0].([]string)
				require.EqualValues(t, "${aws:PrincipalAccount}", vs[0])
			},
		},
		{
			name:    "parse4",
			escaped: false,
			policyText: `{
						  "Version": "2012-10-17",
						  "Statement": [
							{
							  "Effect": "Allow",
							  "Principal": {
								"Federated": "cognito-identity.amazonaws.com"
							  },
							  "Action": "sts:AssumeRoleWithWebIdentity",
							  "Condition": {
								"StringEquals": {
								  "cognito-identity.amazonaws.com:aud": "us-west-2:7e9abc23-035e-49e7-a54a-2f850581930c"
								},
								"ForAnyValue:StringLike": {
								  "cognito-identity.amazonaws.com:amr": "authenticated"
								}
							  }
							}
						  ]
						}`,
			verificationLogic: func(t *testing.T, a *AwsParser) {
				policies, err := a.GetPolicy()
				require.NoError(t, err)
				require.Len(t, policies, 1)
				require.True(t, policies[0].Allowed)
				require.Len(t, policies[0].Subjects, 1)
				require.EqualValues(t, "cognito-identity.amazonaws.com", policies[0].Subjects[0])
				require.Len(t, policies[0].NotSubjects, 0)
				require.Len(t, policies[0].NotActions, 0)
				require.Len(t, policies[0].Resources, 0)
				require.Len(t, policies[0].NotResources, 0)
				require.Len(t, policies[0].Actions, 1)
				require.EqualValues(t, "sts:AssumeRoleWithWebIdentity", policies[0].Actions[0])

				require.Len(t, policies[0].Condition, 2)

				require.EqualValues(t, "StringEquals", policies[0].Condition[0].Operation)
				require.EqualValues(t, "cognito-identity.amazonaws.com:aud", policies[0].Condition[0].Key[0])
				require.Len(t, policies[0].Condition[0].Value, 1)
				require.EqualValues(t, "string", policies[0].Condition[0].Type[0])
				vs := policies[0].Condition[0].Value[0].([]string)
				require.EqualValues(t, "us-west-2:7e9abc23-035e-49e7-a54a-2f850581930c", vs[0])

				require.EqualValues(t, "ForAnyValue:StringLike", policies[0].Condition[1].Operation)
				require.EqualValues(t, "cognito-identity.amazonaws.com:amr", policies[0].Condition[1].Key[0])
				require.Len(t, policies[0].Condition[1].Value, 1)
				require.EqualValues(t, "string", policies[0].Condition[1].Type[0])
				vs = policies[0].Condition[1].Value[0].([]string)
				require.EqualValues(t, "authenticated", vs[0])
			},
		},
		{
			name:    "parse5",
			escaped: false,
			policyText: `{
						  "Statement": [
							{
							  "Effect": "Allow"
							}
						  ],
						  "Version": "2012-10-17"
						}`,
			verificationLogic: func(t *testing.T, a *AwsParser) {
				policies, err := a.GetPolicy()
				require.NoError(t, err)
				require.Len(t, policies, 1)
				require.True(t, policies[0].Allowed)
				require.Equal(t, policies[0].Version, "2012-10-17")
			},
		},
		{
			name: "policy.go value BlockStatement",
			policyText: `{
						"Statement": [
							{
								"Effect": "Allow",
								"Action": "*",
								"Resource": "*"
							}
						]
					}`,
			escaped: false,
			verificationLogic: func(t *testing.T, a *AwsParser) {
				require.NoError(t, a.error)
				require.True(t, a.parsed)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policyText := tt.policyText
			a, err := NewAwsPolicyParser(policyText, tt.escaped)
			require.NoError(t, err)
			err = a.Parse()
			require.NoError(t, err)
			tt.verificationLogic(t, a)
		})
	}
}

func TestAwsParser_Parse(t *testing.T) {
	defer log.SetLevel(log.CurrentLevel())
	log.SetLevel(log.DebugLevel)

	policyText := `{
	  "Version": "2012-10-17",
	  "Statement": [
	    {
	      "Effect": "Deny",
	      "Action": "iam:CreateUser",
	      "Resource": "*"
	    },
	    {
	      "Effect": "Allow",
	      "Action": ["*"],
	      "Resource": "*"
	    }
	  ]
	}`

	a, err := NewAwsPolicyParser(policyText, false)
	require.NoError(t, err)

	err = a.Parse()
	require.NoError(t, err)

	policies, err := a.GetPolicy()
	require.NoError(t, err)

	for index, pol := range policies {
		log.Infof("pol #%d: %+v", index, pol)
	}

	require.Len(t, policies, 2)
	require.False(t, policies[0].Allowed)
	require.Len(t, policies[0].Subjects, 0)
	require.Len(t, policies[0].NotSubjects, 0)
	require.Len(t, policies[0].NotActions, 0)
	require.Len(t, policies[0].NotResources, 0)
	require.Len(t, policies[0].Actions, 1)
	require.EqualValues(t, "iam:CreateUser", policies[0].Actions[0])
	require.Len(t, policies[0].Resources, 1)
	require.EqualValues(t, "<.*>", policies[0].Resources[0])

	require.True(t, policies[1].Allowed)
	require.Len(t, policies[1].Subjects, 0)
	require.Len(t, policies[1].NotSubjects, 0)
	require.Len(t, policies[1].NotActions, 0)
	require.Len(t, policies[1].NotResources, 0)
	require.Len(t, policies[1].Actions, 1)
	require.EqualValues(t, "<.*>", policies[1].Actions[0])
	require.Len(t, policies[1].Resources, 1)
	require.EqualValues(t, "<.*>", policies[1].Resources[0])
}

func TestAwsParser_Parse2(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	policyText := `{
	  "Version": "2012-10-17",
	  "Statement": [
	    {
	      "Effect": "Allow",
	      "Action": ["iam:CreateUser", "iam:RemoveUser"],
	      "Resource": "*"
	    }
	  ]
	}`

	a, err := NewAwsPolicyParser(policyText, false)
	require.NoError(t, err)

	err = a.Parse()
	require.NoError(t, err)

	policies, err := a.GetPolicy()
	require.NoError(t, err)

	for index, pol := range policies {
		log.Infof("pol #%d: %+v", index, pol)
	}

	require.Len(t, policies, 1)
	require.True(t, policies[0].Allowed)
	require.Len(t, policies[0].Subjects, 0)
	require.Len(t, policies[0].NotSubjects, 0)
	require.Len(t, policies[0].NotActions, 0)
	require.Len(t, policies[0].NotResources, 0)
	require.Len(t, policies[0].Actions, 2)
	require.EqualValues(t, "iam:CreateUser", policies[0].Actions[0])
	require.EqualValues(t, "iam:RemoveUser", policies[0].Actions[1])
	require.Len(t, policies[0].Resources, 1)
	require.EqualValues(t, "<.*>", policies[0].Resources[0])
}

func TestAwsParser_Parse3(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	policyText := `

	{
	  "Version": "2012-10-17",
	  "Statement": [
	    {
	      "Sid": "IAMRoleProvisioningActions",
	      "Effect": "Allow",
	      "Action": [
	        "iam:AttachRolePolicy",
	        "iam:CreateRole",
	        "iam:PutRolePolicy",
	        "iam:UpdateRole",
	        "iam:UpdateRoleDescription",
	        "iam:UpdateAssumeRolePolicy"
	      ],
	      "Resource": [
	        "arn:aws:iam::*:role/aws-reserved/sso.amazonaws.com/*"
	      ],
	      "Condition": {
	        "StringNotEquals": {
	          "aws:PrincipalOrgMasterAccountId": "${aws:PrincipalAccount}"
	        }
	      }
	    }
	  ]
	}`

	a, err := NewAwsPolicyParser(policyText, false)
	require.NoError(t, err)

	err = a.Parse()
	require.NoError(t, err)

	policies, err := a.GetPolicy()
	require.NoError(t, err)

	for index, pol := range policies {
		log.Infof("pol #%d: %+v", index, pol)
	}

	require.Len(t, policies, 1)
	require.True(t, policies[0].Allowed)
	require.Len(t, policies[0].Subjects, 0)
	require.Len(t, policies[0].NotSubjects, 0)
	require.Len(t, policies[0].NotActions, 0)
	require.Len(t, policies[0].NotResources, 0)
	require.Len(t, policies[0].Actions, 6)
	require.EqualValues(t, "iam:AttachRolePolicy", policies[0].Actions[0])
	require.EqualValues(t, "iam:CreateRole", policies[0].Actions[1])
	require.EqualValues(t, "iam:PutRolePolicy", policies[0].Actions[2])
	require.EqualValues(t, "iam:UpdateRole", policies[0].Actions[3])
	require.EqualValues(t, "iam:UpdateRoleDescription", policies[0].Actions[4])
	require.EqualValues(t, "iam:UpdateAssumeRolePolicy", policies[0].Actions[5])
	require.Len(t, policies[0].Resources, 1)
	require.EqualValues(t, "arn:aws:iam::<.*>:role/aws-reserved/sso.amazonaws.com/<.*>", policies[0].Resources[0])

	require.Len(t, policies[0].Condition, 1)

	require.EqualValues(t, "StringNotEquals", policies[0].Condition[0].Operation)
	require.EqualValues(t, "aws:PrincipalOrgMasterAccountId", policies[0].Condition[0].Key[0])
	require.Len(t, policies[0].Condition[0].Value, 1)
	require.EqualValues(t, "string", policies[0].Condition[0].Type[0])
	vs := policies[0].Condition[0].Value[0].([]string)
	require.EqualValues(t, "${aws:PrincipalAccount}", vs[0])
}

func TestAwsParser_Parse4(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	policyText := `

	{
	  "Version": "2012-10-17",
	  "Statement": [
	    {
	      "Effect": "Allow",
	      "Principal": {
	        "Federated": "cognito-identity.amazonaws.com"
	      },
	      "Action": "sts:AssumeRoleWithWebIdentity",
	      "Condition": {
	        "StringEquals": {
	          "cognito-identity.amazonaws.com:aud": "us-west-2:7e9abc23-035e-49e7-a54a-2f850581930c"
	        },
	        "ForAnyValue:StringLike": {
	          "cognito-identity.amazonaws.com:amr": "authenticated"
	        }
	      }
	    }
	  ]
	}`

	a, err := NewAwsPolicyParser(policyText, false)
	require.NoError(t, err)

	err = a.Parse()
	require.NoError(t, err)

	policies, err := a.GetPolicy()
	require.NoError(t, err)

	for index, pol := range policies {
		log.Infof("pol #%d: %+v", index, pol)
	}

	require.Len(t, policies, 1)
	require.True(t, policies[0].Allowed)
	require.Len(t, policies[0].Subjects, 1)
	require.EqualValues(t, "cognito-identity.amazonaws.com", policies[0].Subjects[0])
	require.Len(t, policies[0].NotSubjects, 0)
	require.Len(t, policies[0].NotActions, 0)
	require.Len(t, policies[0].Resources, 0)
	require.Len(t, policies[0].NotResources, 0)
	require.Len(t, policies[0].Actions, 1)
	require.EqualValues(t, "sts:AssumeRoleWithWebIdentity", policies[0].Actions[0])

	require.Len(t, policies[0].Condition, 2)

	require.EqualValues(t, "StringEquals", policies[0].Condition[0].Operation)
	require.EqualValues(t, "cognito-identity.amazonaws.com:aud", policies[0].Condition[0].Key[0])
	require.Len(t, policies[0].Condition[0].Value, 1)
	require.EqualValues(t, "string", policies[0].Condition[0].Type[0])
	vs := policies[0].Condition[0].Value[0].([]string)
	require.EqualValues(t, "us-west-2:7e9abc23-035e-49e7-a54a-2f850581930c", vs[0])

	require.EqualValues(t, "ForAnyValue:StringLike", policies[0].Condition[1].Operation)
	require.EqualValues(t, "cognito-identity.amazonaws.com:amr", policies[0].Condition[1].Key[0])
	require.Len(t, policies[0].Condition[1].Value, 1)
	require.EqualValues(t, "string", policies[0].Condition[1].Type[0])
	vs = policies[0].Condition[1].Value[0].([]string)
	require.EqualValues(t, "authenticated", vs[0])
}

func TestAwsParser_Parse5(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	encodedText := `%7B%0A%20%20%20%20%22Version%22%3A%20%222012-10-17%22%2C%0A%20%20%20%20%22Statement%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22ec2%3ADescribeSpotFleetRequests%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22ec2%3AModifySpotFleetRequest%22%0A%20%20%20%20%20%20%20%20%20%20%20%20%5D%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22%2A%22%0A%20%20%20%20%20%20%20%20%20%20%20%20%5D%0A%20%20%20%20%20%20%20%20%7D%2C%0A%20%20%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22cloudwatch%3ADescribeAlarms%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22cloudwatch%3APutMetricAlarm%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22cloudwatch%3ADeleteAlarms%22%0A%20%20%20%20%20%20%20%20%20%20%20%20%5D%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22%2A%22%0A%20%20%20%20%20%20%20%20%20%20%20%20%5D%0A%20%20%20%20%20%20%20%20%7D%2C%0A%20%20%20%20%20%20%20%20%7B%20%0A%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%20%0A%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%22iam%3ACreateServiceLinkedRole%22%2C%20%0A%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%22arn%3Aaws%3Aiam%3A%3A%2A%3Arole%2Faws-service-role%2Fec2.application-autoscaling.amazonaws.com%2FAWSServiceRoleForApplicationAutoScaling_EC2SpotFleetRequest%22%2C%20%0A%20%20%20%20%20%20%20%20%20%20%22Condition%22%3A%20%7B%20%0A%20%20%20%20%20%20%20%20%20%20%20%20%22StringLike%22%3A%20%7B%20%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AAWSServiceName%22%3A%20%22ec2.application-autoscaling.amazonaws.com%22%20%0A%20%20%20%20%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%20%20%20%20%7D%20%0A%20%20%20%20%5D%0A%7D`
	/*
			url decoded policy:
		{
		    "Version": "2012-10-17",
		    "Statement": [
		        {
		            "Effect": "Allow",
		            "Action": [
		                "ec2:DescribeSpotFleetRequests",
		                "ec2:ModifySpotFleetRequest"
		            ],
		            "Resource": [
		                "*"
		            ]
		        },
		        {
		            "Effect": "Allow",
		            "Action": [
		                "cloudwatch:DescribeAlarms",
		                "cloudwatch:PutMetricAlarm",
		                "cloudwatch:DeleteAlarms"
		            ],
		            "Resource": [
		                "*"
		            ]
		        },
		        {
		          "Effect": "Allow",
		          "Action": "iam:CreateServiceLinkedRole",
		          "Resource": "arn:aws:iam::*:role/aws-service-role/ec2.application-autoscaling.amazonaws.com/AWSServiceRoleForApplicationAutoScaling_EC2SpotFleetRequest",
		          "Condition": {
		            "StringLike": {
		              "iam:AWSServiceName": "ec2.application-autoscaling.amazonaws.com"
		            }
		          }
		        }
		    ]
		}
	*/

	a, err := NewAwsPolicyParser(encodedText, true)
	require.NoError(t, err)

	err = a.Parse()
	require.NoError(t, err)

	policies, err := a.GetPolicy()
	require.NoError(t, err)

	for index, pol := range policies {
		log.Infof("pol #%d: %+v", index, pol)
	}

	require.Len(t, policies, 3)

	actions := []int{2, 3, 1}
	resources := []int{1, 1, 1}
	conditions := []int{0, 0, 1}

	for index, p := range policies {
		require.Len(t, p.Actions, actions[index])
		require.Len(t, p.Resources, resources[index])
		require.Len(t, p.Condition, conditions[index])
	}
}

func TestAwsParser_Parse6(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	encodedText := `%7B%0A%20%20%20%20%22Version%22%3A%20%222012-10-17%22%2C%0A%20%20%20%20%22Statement%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22ec2%3ADescribeSpotFleetRequests%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22ec2%3AModifySpotFleetRequest%22%0A%20%20%20%20%20%20%20%20%20%20%20%20%5D%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22%2A%22%0A%20%20%20%20%20%20%20%20%20%20%20%20%5D%0A%20%20%20%20%20%20%20%20%7D%2C%0A%20%20%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22cloudwatch%3ADescribeAlarms%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22cloudwatch%3APutMetricAlarm%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22cloudwatch%3ADeleteAlarms%22%0A%20%20%20%20%20%20%20%20%20%20%20%20%5D%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22%2A%22%0A%20%20%20%20%20%20%20%20%20%20%20%20%5D%0A%20%20%20%20%20%20%20%20%7D%2C%0A%20%20%20%20%20%20%20%20%7B%20%0A%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%20%0A%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%22iam%3ACreateServiceLinkedRole%22%2C%20%0A%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%22arn%3Aaws%3Aiam%3A%3A%2A%3Arole%2Faws-service-role%2Fec2.application-autoscaling.amazonaws.com%2FAWSServiceRoleForApplicationAutoScaling_EC2SpotFleetRequest%22%2C%20%0A%20%20%20%20%20%20%20%20%20%20%22Condition%22%3A%20%7B%20%0A%20%20%20%20%20%20%20%20%20%20%20%20%22StringLike%22%3A%20%7B%20%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AAWSServiceName%22%3A%20%22ec2.application-autoscaling.amazonaws.com%22%20%0A%20%20%20%20%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%20%20%20%20%7D%20%0A%20%20%20%20%5D%0A%7D`

	a, err := NewAwsPolicyParser(encodedText, true)
	require.NoError(t, err)

	err = a.Parse()
	require.NoError(t, err)

	policies, err := a.GetPolicy()
	require.NoError(t, err)

	for index, pol := range policies {
		log.Infof("pol #%d: %+v", index, pol)
	}

	require.Len(t, policies, 3)

	actions := []int{2, 3, 1}
	resources := []int{1, 1, 1}
	conditions := []int{0, 0, 1}

	for index, p := range policies {
		require.Len(t, p.Actions, actions[index])
		require.Len(t, p.Resources, resources[index])
		require.Len(t, p.Condition, conditions[index])
	}
}

func TestAwsParser_Parse7(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	encodedText := `%7B%0A%20%20%20%20%22Version%22%3A%20%222012-10-17%22%2C%0A%20%20%20%20%22Statement%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Sid%22%3A%20%22VisualEditor0%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%22s3%3A%2A%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%22arn%3Aaws%3As3%3A%3A%3Abcone-us-west-2-employee%22%0A%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%5D%0A%7D`

	a, err := NewAwsPolicyParser(encodedText, true)
	require.NoError(t, err)

	err = a.Parse()
	require.NoError(t, err)

	policies, err := a.GetPolicy()
	require.NoError(t, err)

	for index, pol := range policies {
		log.Infof("pol #%d: %+v", index, pol)
	}

	require.Len(t, policies, 1)
}

func TestAwsParser_Parse8(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	policyText := `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": "iam:CreateUser",
      "Resource": "*",
      "Condition": {
          "True": {
			"mfaAuthenticated": [false, true]
          }
      }
    }
  ]
}`
	a, err := NewAwsPolicyParser(policyText, false)
	require.NoError(t, err)

	err = a.Parse()
	require.NoError(t, err)

	policies, err := a.GetPolicy()
	require.NoError(t, err)

	for index, pol := range policies {
		log.Infof("pol #%d: %+v", index, pol)
	}

	require.Len(t, policies, 1)
	require.False(t, policies[0].Allowed)
	require.Len(t, policies[0].Subjects, 0)
	require.Len(t, policies[0].NotSubjects, 0)
	require.Len(t, policies[0].NotActions, 0)
	require.Len(t, policies[0].NotResources, 0)
	require.Len(t, policies[0].Actions, 1)
	require.EqualValues(t, "iam:CreateUser", policies[0].Actions[0])
	require.Len(t, policies[0].Resources, 1)
	require.EqualValues(t, "<.*>", policies[0].Resources[0])

	require.Len(t, policies[0].Condition, 1)

	require.EqualValues(t, "True", policies[0].Condition[0].Operation)
	require.EqualValues(t, "mfaAuthenticated", policies[0].Condition[0].Key[0])
	require.Len(t, policies[0].Condition[0].Value[0], 2)
	require.EqualValues(t, "bool", policies[0].Condition[0].Type[0])
	vs := policies[0].Condition[0].Value[0].([]bool)
	require.EqualValues(t, false, vs[0])
	require.EqualValues(t, true, vs[1])
}

func TestAwsParser_Parse9(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	var policyText = `
{
	"Version": "2012-10-17",
	"Statement": [
		{
			"Condition": {
				"StringEquals": {
					"secretsmanager:ResourceTag/aws:secretsmanager:owningService": "redshift",
					"aws:ResourceAccount": "${aws:PrincipalAccount}"
				}
			}
		}
	]
}`

	a, err := NewAwsPolicyParser(policyText, false)
	require.NoError(t, err)

	err = a.Parse()
	require.NoError(t, err)

	policies, err := a.GetPolicy()
	require.NoError(t, err)

	for index, pol := range policies {
		log.Infof("pol #%d: %+v", index, pol)
	}

	require.Len(t, policies, 1)
	require.Len(t, policies[0].Condition, 1)
	require.EqualValues(t, "StringEquals", policies[0].Condition[0].Operation)
	require.Len(t, policies[0].Condition[0].Key, 2)
	require.Len(t, policies[0].Condition[0].Value, 2)
	require.Len(t, policies[0].Condition[0].Type, 2)
	require.EqualValues(
		t,
		"secretsmanager:ResourceTag/aws:secretsmanager:owningService",
		policies[0].Condition[0].Key[0],
	)
	require.EqualValues(t, "aws:ResourceAccount", policies[0].Condition[0].Key[1])
	require.EqualValues(t, "string", policies[0].Condition[0].Type[0])
	require.EqualValues(t, "string", policies[0].Condition[0].Type[1])
	require.EqualValues(t, "redshift", policies[0].Condition[0].Value[0].([]string)[0])
	require.EqualValues(t, "${aws:PrincipalAccount}", policies[0].Condition[0].Value[1].([]string)[0])

}

func TestAwsParser_Parse10(t *testing.T) {
	policyText := `{
  "Statement": [
    {
      "Action": [
        "acm:Describe*",
        "acm:Get*",
        "acm:List*",
        "acm:Request*",
        "acm:Resend*",
        "autoscaling:*",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:ListPublicKeys",
        "cloudtrail:ListTags",
        "cloudtrail:LookupEvents",
        "cloudtrail:StartLogging",
        "cloudtrail:StopLogging",
        "codedeploy:BatchGet*",
        "codedeploy:Get*",
        "codedeploy:List*",
        "codecommit:BatchGet*",
        "codecommit:BatchDescribe*",
        "codecommit:Describe*",
        "codecommit:Get*",
        "codecommit:List*",
        "cognito-idp:List*",
        "config:Deliver*",
        "config:Describe*",
        "config:Get*",
        "config:List*",
        "directconnect:Describe*",
        "dynamodb:DescribeBackup",
        "dynamodb:DescribeContinuousBackups",
        "dynamodb:DescribeGlobalTable",
        "dynamodb:DescribeGlobalTableSettings",
        "dynamodb:DescribeLimits",
        "dynamodb:DescribeReservedCapacity",
        "dynamodb:DescribeReservedCapacityOfferings",
        "dynamodb:DescribeStream",
        "dynamodb:DescribeTable",
        "dynamodb:DescribeTimeToLive",
        "dynamodb:ListBackups",
        "dynamodb:ListGlobalTables",
        "dynamodb:ListStreams",
        "dynamodb:ListTables",
        "dynamodb:ListTagsOfResource",
        "ec2:Describe*",
        "ecr:BatchCheckLayerAvailability",
        "ecr:BatchGetImage",
        "ecr:DescribeImageScanFindings",
        "ecr:DescribeImages",
        "ecr:DescribeRegistry",
        "ecr:DescribeRepositories",
        "ecr:GetAuthorizationToken",
        "ecr:GetDownloadUrlForLayer",
        "ecr:GetLifecyclePolicy",
        "ecr:GetLifecyclePolicyPreview",
        "ecr:GetRegistryPolicy",
        "ecr:GetRepositoryPolicy",
        "ecr:ListImages",
        "ecr:ListTagsForResource",
        "elasticfilesystem:Describe*",
        "elasticloadbalancing:Describe*",
        "firehose:Describe*",
        "firehose:List*",
        "glacier:DescribeVault",
        "glacier:GetDataRetrievalPolicy",
        "glacier:GetVaultAccessPolicy",
        "glacier:GetVaultLock",
        "glacier:GetVaultNotifications",
        "glacier:ListJobs",
        "glacier:ListMultipartUploads",
        "glacier:ListParts",
        "glacier:ListProvisionedCapacity",
        "glacier:ListTagsForVault",
        "glacier:ListVaults",
        "glue:BatchGetJobs",
        "glue:BatchGetWorkflows",
        "glue:GetClassifier",
        "glue:GetClassifiers",
        "glue:GetCrawler",
        "glue:GetCrawlers",
        "glue:GetDatabase",
        "glue:GetDatabases",
        "glue:GetDataCatalogEncryptionSettings",
        "glue:GetJob",
        "glue:GetJobs",
        "glue:GetJobRun",
        "glue:GetJobRuns",
        "glue:GetPartition",
        "glue:GetPartitions",
        "glue:GetSecurityConfiguration",
        "glue:GetSecurityConfigurations",
        "glue:GetTable",
        "glue:GetTables",
        "glue:GetTableVersion",
        "glue:GetTableVersions",
        "glue:GetTrigger",
        "glue:GetTriggers",
        "glue:GetUserDefinedFunction",
        "glue:GetUserDefinedFunctions",
        "glue:GetWorkflow",
        "glue:GetWorkflowRun",
        "glue:GetWorkflowRunProperties",
        "glue:GetWorkflowRuns",
        "glue:ListCrawlers",
        "glue:ListDevEndpoints",
        "glue:ListJobs",
        "glue:ListTriggers",
        "glue:ListWorkflows",
        "iam:GenerateCredentialReport",
        "iam:Get*",
        "iam:List*",
        "kms:Describe*",
        "kms:Get*",
        "kms:List*",
        "lambda:GetAccountSettings",
        "lambda:GetFunction",
        "lambda:GetFunctionConfiguration",
        "lambda:GetPolicy",
        "lambda:List*",
        "logs:Describe*",
        "logs:Get*",
        "logs:FilterLogEvents",
        "logs:ListTagsLogGroup",
        "logs:StartQuery",
        "logs:StopQuery",
        "logs:TestMetricFilter",
        "organizations:Describe*",
        "organizations:List*",
        "rds:Describe*",
        "rds:ListTagsForResource",
        "redshift:Describe*",
        "redshift:ViewQueriesInConsole",
        "route53:Get*",
        "route53:List*",
        "route53domains:CheckDomainAvailability",
        "route53domains:GetDomainDetail",
        "route53domains:GetOperationDetail",
        "route53domains:ListDomains",
        "route53domains:ListOperations",
        "route53domains:ListTagsForDomain",
        "s3:GetAccelerateConfiguration",
        "s3:GetAccountPublicAccessBlock",
        "s3:GetAnalyticsConfiguration",
        "s3:GetBucket*",
        "s3:GetEncryptionConfiguration",
        "s3:GetInventoryConfiguration",
        "s3:GetLifecycleConfiguration",
        "s3:GetMetricsConfiguration",
        "s3:GetObjectAcl",
        "s3:GetObjectVersionAcl",
        "s3:GetReplicationConfiguration",
        "s3:List*",
        "sns:Get*",
        "sns:List*",
        "sqs:GetQueueAttributes",
        "sqs:GetQueueUrl",
        "sqs:ListDeadLetterSourceQueues",
        "sqs:ListQueueTags",
        "sqs:ListQueues",
        "sqs:ReceiveMessage",
        "tag:Get*"
      ],
      "Effect": "Allow",
      "Resource": [
        "*"
      ]
    },
    {
      "Action": [
        "iam:GetRole",
        "iam:ListRoles",
        "iam:PassRole"
      ],
      "Effect": "Allow",
      "Resource": [
        "arn:aws:iam::*:role/rds-monitoring-role",
        "arn:aws:iam::*:role/ec2-sysadmin-*",
        "arn:aws:iam::*:role/ecr-sysadmin-*",
        "arn:aws:iam::*:role/lambda-sysadmin-*"
      ]
    }
  ],
  "Version": "2012-10-17"
}`
	// Add a simple test body that actually uses the policyText variable
	a, err := NewAwsPolicyParser(policyText, false)
	require.NoError(t, err)

	err = a.Parse()
	require.NoError(t, err)

	policies, err := a.GetPolicy()
	require.NoError(t, err)
	require.NotNil(t, policies)
}

func UnrollError(err error) string {
	errs := []error{err}
	for errors.Unwrap(err) != nil {
		errs = append(errs, errors.Unwrap(err))
		err = errors.Unwrap(err)
	}
	var fmtted []string
	for i := range errs {
		fmtted = append(fmtted, fmt.Sprintf("%T: %s", errs[i], errs[i].Error()))
	}
	return strings.Join(fmtted, ", ")
}

func newParsedAwsParser(t *testing.T, policyText string) *AwsParser {
	t.Helper()

	a, err := NewAwsPolicyParser(policyText, false)
	require.NoError(t, err)
	require.NoError(t, a.Parse())

	return a
}

func firstParsedCondition(t *testing.T, policyText string) policy.Condition {
	t.Helper()

	a := newParsedAwsParser(t, policyText)
	policies, err := a.GetPolicy()
	require.NoError(t, err)
	require.Len(t, policies, 1)
	require.Len(t, policies[0].Condition, 1)

	return policies[0].Condition[0]
}

func TestAwsParser_GetPolicyErrorPaths(t *testing.T) {
	tests := []struct {
		name      string
		parser    *AwsParser
		assertErr func(t *testing.T, err error)
	}{
		{
			name:   "Not Parsed, No Error",
			parser: &AwsParser{},
			assertErr: func(t *testing.T, err error) {
				t.Helper()
				require.Contains(t, err.Error(), "did not parse")
			},
		},
		{
			name:   "Not Parsed, With Error",
			parser: &AwsParser{error: fmt.Errorf("some parse error")},
			assertErr: func(t *testing.T, err error) {
				t.Helper()
				require.EqualError(t, err, "some parse error")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policies, err := tt.parser.GetPolicy()
			require.Error(t, err)
			require.Nil(t, policies)
			tt.assertErr(t, err)
		})
	}
}

func TestAwsParser_JsonErrorPaths(t *testing.T) {
	tests := []struct {
		name   string
		parser *AwsParser
	}{
		{name: "Not Parsed", parser: &AwsParser{}},
		{name: "Parsed, Nil Policies", parser: &AwsParser{parsed: true, policies: nil}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonData, err := tt.parser.Json()
			require.Error(t, err)
			require.Nil(t, jsonData)
			require.Contains(t, err.Error(), "no policies parsed yet")
		})
	}
}

func TestAwsParser_WriteJsonErrorPaths(t *testing.T) {
	tests := []struct {
		name      string
		parser    *AwsParser
		filename  string
		assertErr func(t *testing.T, err error)
	}{
		{
			name:     "Not Parsed",
			parser:   &AwsParser{},
			filename: "somefile.json",
			assertErr: func(t *testing.T, err error) {
				t.Helper()
				require.Contains(t, err.Error(), "no policies parsed yet")
			},
		},
		{
			name:     "Parsed, Nil Policies",
			parser:   &AwsParser{parsed: true, policies: nil},
			filename: "somefile.json",
			assertErr: func(t *testing.T, err error) {
				t.Helper()
				require.Contains(t, err.Error(), "no policies parsed yet")
			},
		},
		{
			name:     "File Exists",
			parser:   &AwsParser{parsed: true, policies: []*policy.Policy{{Id: "p1"}}},
			filename: "aws_parser_test.go",
			assertErr: func(t *testing.T, err error) {
				t.Helper()
				require.Contains(t, err.Error(), "file exists")
			},
		},
		{
			name:     "Cannot Open File",
			parser:   &AwsParser{parsed: true, policies: []*policy.Policy{{Id: "p1"}}},
			filename: "/dev/null/some_invalid_file",
			assertErr: func(t *testing.T, err error) {
				t.Helper()
				require.True(t, os.IsNotExist(err) || strings.Contains(err.Error(), "not a directory"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.parser.WriteJson(tt.filename)
			require.Error(t, err)
			tt.assertErr(t, err)
		})
	}
}

func TestAwsParser_ParseErrorPaths(t *testing.T) {
	tests := []struct {
		name       string
		policyText string
		assertErr  func(t *testing.T, parser *AwsParser, err error)
	}{
		{
			name:       "Invalid Policy Syntax",
			policyText: `{"Version": "2012-10-17", "Statement": [{"Effect": "Allow",}]}`,
			assertErr: func(t *testing.T, parser *AwsParser, err error) {
				t.Helper()
				require.False(t, parser.parsed)
				require.NotNil(t, parser.error)
				var parseErr *participle.UnexpectedTokenError
				require.True(t, errors.As(err, &parseErr))
			},
		},
		{
			name:       "Missing Statement Property",
			policyText: `{"Version": "2012-10-17"}`,
			assertErr: func(t *testing.T, parser *AwsParser, err error) {
				t.Helper()
				require.False(t, parser.parsed)
				require.NotNil(t, parser.error)
				require.Contains(t, err.Error(), "error constructing policy")
				require.Contains(t, parser.error.Error(), "no statements found in policy")
			},
		},
		{
			name:       "Statement Not BlockStatement",
			policyText: `{"Version": "2012-10-17", "Statement": "NotABlock"}`,
			assertErr: func(t *testing.T, parser *AwsParser, err error) {
				t.Helper()
				require.False(t, parser.parsed)
				require.NotNil(t, parser.error)
				require.Contains(t, err.Error(), "error constructing policy")
				require.Contains(t, parser.error.Error(), "statement is not a block statement")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := NewAwsPolicyParser(tt.policyText, false)
			require.NoError(t, err)

			err = a.Parse()
			require.Error(t, err)

			tt.assertErr(t, a, err)
		})
	}
}

func TestAwsParser_ConstructPolicyEdgeCases(t *testing.T) {
	t.Run("Nil AwsPolicy", func(t *testing.T) {
		a := &AwsParser{awsPolicy: nil}
		err := a.constructPolicy(nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "parsed policy AST is nil")
		require.Nil(t, a.policies)
	})

	tests := []struct {
		name       string
		policyText string
	}{
		{
			name: "Empty Statement Elements",
			policyText: `{
			"Statement": [{
				"Effect": "Allow"
			}]
		}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newParsedAwsParser(t, tt.policyText)
			policies, err := a.GetPolicy()
			require.NoError(t, err)
			require.Len(t, policies, 1)
			require.True(t, policies[0].Allowed)
			require.Empty(t, policies[0].Actions)
			require.Empty(t, policies[0].NotActions)
			require.Empty(t, policies[0].Resources)
			require.Empty(t, policies[0].NotResources)
			require.Empty(t, policies[0].Subjects)
			require.Empty(t, policies[0].NotSubjects)
			require.Empty(t, policies[0].Condition)
		})
	}
}

func TestAwsParser_GetAnyOrListNilCases(t *testing.T) {
	a := &AwsParser{}
	tests := []struct {
		name  string
		input *AnyOrList
	}{
		{name: "Nil Input", input: nil},
		{name: "Empty Struct", input: &AnyOrList{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := a.getAnyOrList(tt.input)
			require.Empty(t, result)
		})
	}
}

func TestAwsParser_GetSubjectsNilCases(t *testing.T) {
	a := &AwsParser{}
	tests := []struct {
		name  string
		input *Principal
	}{
		{name: "Nil Input", input: nil},
		{name: "Empty Struct", input: &Principal{}},
		{
			name: "List With Nil Elements",
			input: &Principal{
				List: []*PrincipalList{{Aws: nil, Federated: nil, Canonical: nil, Service: nil}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := a.getSubjects(tt.input)
			require.Empty(t, result)
		})
	}
}

func TestAwsParser_GetConditionCases(t *testing.T) {
	a := &AwsParser{}
	t.Run("Nil Input", func(t *testing.T) {
		require.Nil(t, a.getCondition(nil))
	})

	tests := []struct {
		name       string
		policyText string
		assertCond func(t *testing.T, cond policy.Condition)
	}{
		{
			name: "StringEquals Condition",
			policyText: `{
			"Statement": [{
				"Effect": "Allow",
				"Action": "*",
				"Resource": "*",
				"Condition": {
					"StringEquals": {"aws:userid": "bob"}
				}
			}]
		}`,
			assertCond: func(t *testing.T, cond policy.Condition) {
				t.Helper()
				require.Equal(t, "StringEquals", cond.Operation)
				require.Equal(t, []string{"aws:userid"}, cond.Key)
				require.Equal(t, []string{"string"}, cond.Type)
				require.Len(t, cond.Value, 1)
				val, ok := cond.Value[0].([]string)
				require.True(t, ok)
				require.Equal(t, []string{"bob"}, val)
			},
		},
		{
			name: "Bool Condition",
			policyText: `{
			"Statement": [{
				"Effect": "Allow",
				"Action": "*",
				"Resource": "*",
				"Condition": {
					"Bool": {"aws:SecureTransport": true}
				}
			}]
		}`,
			assertCond: func(t *testing.T, cond policy.Condition) {
				t.Helper()
				require.Equal(t, "Bool", cond.Operation)
				require.Equal(t, []string{"aws:SecureTransport"}, cond.Key)
				require.Equal(t, []string{"bool"}, cond.Type)
				require.Len(t, cond.Value, 1)
				val, ok := cond.Value[0].([]bool)
				require.True(t, ok)
				require.Equal(t, []bool{true}, val)
			},
		},
		{
			name: "Condition With Multiple Values",
			policyText: `{
			"Statement": [{
				"Effect": "Allow",
				"Action": "*",
				"Resource": "*",
				"Condition": {
					"StringEqualsIgnoreCase": {"aws:username": ["alice", "bob"]}
				}
			}]
		}`,
			assertCond: func(t *testing.T, cond policy.Condition) {
				t.Helper()
				require.Equal(t, "StringEqualsIgnoreCase", cond.Operation)
				require.Equal(t, []string{"aws:username"}, cond.Key)
				require.Equal(t, []string{"string"}, cond.Type)
				require.Len(t, cond.Value, 1)
				val, ok := cond.Value[0].([]string)
				require.True(t, ok)
				require.Equal(t, []string{"alice", "bob"}, val)
			},
		},
		{
			name: "Null Condition Check",
			policyText: `{
			"Statement": [{
				"Effect": "Allow",
				"Action": "*",
				"Resource": "*",
				"Condition": {
					"Null": {"aws:TokenIssueTime": false}
				}
			}]
		}`,
			assertCond: func(t *testing.T, cond policy.Condition) {
				t.Helper()
				require.Equal(t, "Null", cond.Operation)
				require.Equal(t, []string{"aws:TokenIssueTime"}, cond.Key)
				require.Equal(t, []string{"bool"}, cond.Type)
				require.Len(t, cond.Value, 1)
				val, ok := cond.Value[0].([]bool)
				require.True(t, ok)
				require.Equal(t, []bool{false}, val)
			},
		},
		{
			name: "NumericEquals Condition",
			policyText: `{
			"Statement": [{
				"Effect": "Allow", "Action": "*", "Resource": "*",
				"Condition": {
					"NumericEquals": {"aws:MultiFactorAuthAge": 1000}
				}
			}]
		}`,
			assertCond: func(t *testing.T, cond policy.Condition) {
				t.Helper()
				require.Equal(t, "NumericEquals", cond.Operation)
				require.Equal(t, []string{"aws:MultiFactorAuthAge"}, cond.Key)
				require.Equal(t, []string{"int64"}, cond.Type)
				require.Len(t, cond.Value, 1)
				val, ok := cond.Value[0].([]int64)
				require.True(t, ok)
				require.Equal(t, []int64{1000}, val)
			},
		},
		{
			name: "DateGreaterThan Condition",
			policyText: `{
			"Statement": [{
				"Effect": "Allow", "Action": "*", "Resource": "*",
				"Condition": {
					"DateGreaterThan": {"aws:CurrentTime": "2024-01-01T00:00:00Z"}
				}
			}]
		}`,
			assertCond: func(t *testing.T, cond policy.Condition) {
				t.Helper()
				require.Equal(t, "DateGreaterThan", cond.Operation)
				require.Equal(t, []string{"aws:CurrentTime"}, cond.Key)
				require.Equal(t, []string{"string"}, cond.Type)
				require.Len(t, cond.Value, 1)
				val, ok := cond.Value[0].([]string)
				require.True(t, ok)
				require.Equal(t, []string{"2024-01-01T00:00:00Z"}, val)
			},
		},
		{
			name: "StringLike Condition",
			policyText: `{
			"Statement": [{
				"Effect": "Allow", "Action": "*", "Resource": "*",
				"Condition": {
					"StringLike": {"s3:prefix": "home/*"}
				}
			}]
		}`,
			assertCond: func(t *testing.T, cond policy.Condition) {
				t.Helper()
				require.Equal(t, "StringLike", cond.Operation)
				require.Equal(t, []string{"s3:prefix"}, cond.Key)
				require.Len(t, cond.Value, 1)
				val, ok := cond.Value[0].([]string)
				require.True(t, ok)
				require.Equal(t, []string{"home/*"}, val)
			},
		},
		{
			name: "IpAddress Condition",
			policyText: `{
			"Statement": [{
				"Effect": "Allow", "Action": "*", "Resource": "*",
				"Condition": {
					"IpAddress": {"aws:SourceIp": "192.0.2.0/24"}
				}
			}]
		}`,
			assertCond: func(t *testing.T, cond policy.Condition) {
				t.Helper()
				require.Equal(t, "IpAddress", cond.Operation)
				require.Equal(t, []string{"aws:SourceIp"}, cond.Key)
				require.Len(t, cond.Value, 1)
				val, ok := cond.Value[0].([]string)
				require.True(t, ok)
				require.Equal(t, []string{"192.0.2.0/24"}, val)
			},
		},
		{
			name: "ArnEquals Condition",
			policyText: `{
			"Statement": [{
				"Effect": "Allow", "Action": "*", "Resource": "*",
				"Condition": {
					"ArnEquals": {"aws:SourceArn": "arn:aws:sns:*:123456789012:topic"}
				}
			}]
		}`,
			assertCond: func(t *testing.T, cond policy.Condition) {
				t.Helper()
				require.Equal(t, "ArnEquals", cond.Operation)
				require.Equal(t, []string{"aws:SourceArn"}, cond.Key)
				require.Len(t, cond.Value, 1)
				val, ok := cond.Value[0].([]string)
				require.True(t, ok)
				require.Equal(t, []string{"arn:aws:sns:*:123456789012:topic"}, val)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cond := firstParsedCondition(t, tt.policyText)
			tt.assertCond(t, cond)
		})
	}

	t.Run("Condition With Invalid Value Type", func(t *testing.T) {
		policyText := `{
			"Statement": [{
				"Effect": "Allow", "Action": "*", "Resource": "*",
				"Condition": {
					"StringEquals": {"aws:TagKeys": {"key": "value"}}
				}
			}]
		}`
		parser, err := NewAwsPolicyParser(policyText, false)
		require.NoError(t, err)

		err = parser.Parse()
		require.Error(t, err)

		if strings.Contains(err.Error(), "error constructing policy") {
			log.Debugf("Construction error (expected for hitting default case): %v", err)
			return
		}

		var parseErr *participle.UnexpectedTokenError
		require.True(t, errors.As(err, &parseErr))
	})
}

// FuzzParsePolicyText is a fuzzing test for the AWS policy parser
func FuzzParsePolicyText(f *testing.F) {
	// Add seed corpus
	f.Add(`{
  "Statement": [
    {
      "Action": [
        "iam:Get*",
        "iam:List*"
      ],
      "Effect": "Allow",
      "Resource": ["*"]
    }
  ],
  "Version": "2012-10-17"
}`, false)

	// Run the fuzzer
	f.Fuzz(func(t *testing.T, policyText string, urlDecode bool) {
		// t.Parallel()
		a, err := NewAwsPolicyParser(policyText, urlDecode)
		if err != nil {
			switch {
			case strings.Contains(err.Error(), "invalid URL escape"):
				return
			default:
				t.Error(UnrollError(err))
				t.Fail()
			}
		}
		err = a.Parse()
		if err != nil {
			t.Log(UnrollError(err))
			var pute *participle.UnexpectedTokenError
			var le *lexer.Error
			var ppe *participle.ParseError
			switch {
			case errors.As(err, &pute):
				return
			case errors.As(err, &le):
				return
			case errors.As(err, &ppe):
				return
			default:
				t.Fail()
			}
		}
	})
}
