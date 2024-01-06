package aws

import (
	"testing"

	"net/url"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// TestAwsParse is the template test function, that all other tests in this package should be included into
func TestAwsParse(t *testing.T) {
	defer log.SetLevel(log.GetLevel())
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			policyText := tt.policyText
			a, err := NewAwsPolicyParser(policyText, tt.escaped)
			require.NoError(t, err)
			err = a.Parse()
			require.NoError(t, err)
			tt.verificationLogic(t, a)
		})
	}
}

/*
	func TestAwsParser_Parse(t *testing.T) {
		defer log.SetLevel(log.GetLevel())
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
*/
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

	encodedText := `%7B%0A%20%20%20%20%22Version%22%3A%20%222012-10-17%22%2C%0A%20%20%20%20%22Statement%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22ec2%3ADescribeSpotFleetRequests%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22ec2%3AModifySpotFleetRequest%22%0A%20%20%20%20%20%20%20%20%20%20%20%20%5D%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22%2A%22%0A%20%20%20%20%20%20%20%20%20%20%20%20%5D%0A%20%20%20%20%20%20%20%20%7D%2C%0A%20%20%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22cloudwatch%3ADescribeAlarms%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22cloudwatch%3APutMetricAlarm%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22cloudwatch%3ADeleteAlarms%22%0A%20%20%20%20%20%20%20%20%20%20%20%20%5D%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22%2A%22%0A%20%20%20%20%20%20%20%20%20%20%20%20%5D%0A%20%20%20%20%20%20%20%20%7D%2C%0A%20%20%20%20%20%20%20%20%7B%20%0A%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%22iam%3ACreateServiceLinkedRole%22%2C%20%0A%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%20%0A%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%22arn%3Aaws%3Aiam%3A%3A%2A%3Arole%2Faws-service-role%2Fec2.application-autoscaling.amazonaws.com%2FAWSServiceRoleForApplicationAutoScaling_EC2SpotFleetRequest%22%2C%20%0A%20%20%20%20%20%20%20%20%20%20%22Condition%22%3A%20%7B%20%0A%20%20%20%20%20%20%20%20%20%20%20%20%22StringLike%22%3A%20%7B%20%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AAWSServiceName%22%3A%20%22ec2.application-autoscaling.amazonaws.com%22%20%0A%20%20%20%20%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%20%20%20%20%7D%20%0A%20%20%20%20%5D%0A%7D`

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
        "cloudwatch:*",
        "codecommit:BatchGetRepositories",
        "codecommit:CreateBranch",
        "codecommit:CreateRepository",
        "codecommit:Get*",
        "codecommit:GitPull",
        "codecommit:GitPush",
        "codecommit:List*",
        "codecommit:Put*",
        "codecommit:Test*",
        "codecommit:Update*",
        "codedeploy:*",
        "codepipeline:*",
        "config:*",
        "ds:*",
        "ec2:Allocate*",
        "ec2:AssignPrivateIpAddresses*",
        "ec2:Associate*",
        "ec2:Allocate*",
        "ec2:AttachInternetGateway",
        "ec2:AttachNetworkInterface",
        "ec2:AttachVpnGateway",
        "ec2:Bundle*",
        "ec2:Cancel*",
        "ec2:Copy*",
        "ec2:CreateCustomerGateway",
        "ec2:CreateDhcpOptions",
        "ec2:CreateFlowLogs",
        "ec2:CreateImage",
        "ec2:CreateInstanceExportTask",
        "ec2:CreateInternetGateway",
        "ec2:CreateKeyPair",
        "ec2:CreateLaunchTemplate",
        "ec2:CreateLaunchTemplateVersion",
        "ec2:CreateNatGateway",
        "ec2:CreateNetworkInterface",
        "ec2:CreatePlacementGroup",
        "ec2:CreateReservedInstancesListing",
        "ec2:CreateRoute",
        "ec2:CreateRouteTable",
        "ec2:CreateSecurityGroup",
        "ec2:CreateSnapshot",
        "ec2:CreateSpotDatafeedSubscription",
        "ec2:CreateSubnet",
        "ec2:CreateTags",
        "ec2:CreateVolume",
        "ec2:CreateVpc",
        "ec2:CreateVpcEndpoint",
        "ec2:CreateVpnConnection",
        "ec2:CreateVpnConnectionRoute",
        "ec2:CreateVpnGateway",
        "ec2:DeleteFlowLogs",
        "ec2:DeleteKeyPair",
        "ec2:DeleteLaunchTemplate",
        "ec2:DeleteLaunchTemplateVersions",
        "ec2:DeleteNatGateway",
        "ec2:DeleteNetworkInterface",
        "ec2:DeletePlacementGroup",
        "ec2:DeleteSnapshot",
        "ec2:DeleteSpotDatafeedSubscription",
        "ec2:DeleteSubnet",
        "ec2:DeleteTags",
        "ec2:DeleteVpc",
        "ec2:DeleteVpcEndpoints",
        "ec2:DeleteVpnConnection",
        "ec2:DeleteVpnConnectionRoute",
        "ec2:DeleteVpnGateway",
        "ec2:DeregisterImage",
        "ec2:Describe*",
        "ec2:DetachInternetGateway",
        "ec2:DetachNetworkInterface",
        "ec2:DetachVpnGateway",
        "ec2:DisableVgwRoutePropagation",
        "ec2:DisableVpcClassicLinkDnsSupport",
        "ec2:DisassociateAddress",
        "ec2:DisassociateRouteTable",
        "ec2:EnableVgwRoutePropagation",
        "ec2:EnableVolumeIO",
        "ec2:EnableVpcClassicLinkDnsSupport",
        "ec2:GetConsoleOutput",
        "ec2:GetHostReservationPurchasePreview",
        "ec2:GetLaunchTemplateData",
        "ec2:GetPasswordData",
        "ec2:Import*",
        "ec2:Modify*",
        "ec2:MonitorInstances",
        "ec2:MoveAddressToVpc",
        "ec2:Purchase*",
        "ec2:RegisterImage",
        "ec2:Release*",
        "ec2:Replace*",
        "ec2:ReportInstanceStatus",
        "ec2:Request*",
        "ec2:Reset*",
        "ec2:RestoreAddressToClassic",
        "ec2:RunScheduledInstances",
        "ec2:UnassignPrivateIpAddresses",
        "ec2:UnmonitorInstances",
        "ec2:UpdateSecurityGroupRuleDescriptionsEgress",
        "ec2:UpdateSecurityGroupRuleDescriptionsIngress",
        "elasticloadbalancing:*",
        "events:*",
        "iam:GetAccount*",
        "iam:GetContextKeys*",
        "iam:GetCredentialReport",
        "iam:ListAccountAliases",
        "iam:ListGroups",
        "iam:ListOpenIDConnectProviders",
        "iam:ListPolicies",
        "iam:ListPoliciesGrantingServiceAccess",
        "iam:ListRoles",
        "iam:ListSAMLProviders",
        "iam:ListServerCertificates",
        "iam:Simulate*",
        "iam:UpdateServerCertificate",
        "iam:UpdateSigningCertificate",
        "kinesis:ListStreams",
        "kinesis:PutRecord",
        "kms:CreateAlias",
        "kms:CreateKey",
        "kms:DeleteAlias",
        "kms:Describe*",
        "kms:GenerateRandom",
        "kms:Get*",
        "kms:List*",
        "kms:Encrypt",
        "kms:ReEncrypt*",
        "lambda:Create*",
        "lambda:Delete*",
        "lambda:Get*",
        "lambda:InvokeFunction",
        "lambda:List*",
        "lambda:PublishVersion",
        "lambda:Update*",
        "logs:*",
        "rds:Describe*",
        "rds:ListTagsForResource",
        "route53:*",
        "route53domains:*",
        "ses:*",
        "sns:*",
        "sqs:*",
        "trustedadvisor:*"
      ],
      "Effect": "Allow",
      "Resource": "*"
    },
    {
      "Action": [
        "ec2:AcceptVpcPeeringConnection",
        "ec2:AttachClassicLinkVpc",
        "ec2:AttachVolume",
        "ec2:AuthorizeSecurityGroupEgress",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:CreateVpcPeeringConnection",
        "ec2:DeleteCustomerGateway",
        "ec2:DeleteDhcpOptions",
        "ec2:DeleteInternetGateway",
        "ec2:DeleteNetworkAcl*",
        "ec2:DeleteRoute",
        "ec2:DeleteRouteTable",
        "ec2:DeleteSecurityGroup",
        "ec2:DeleteVolume",
        "ec2:DeleteVpcPeeringConnection",
        "ec2:DetachClassicLinkVpc",
        "ec2:DetachVolume",
        "ec2:DisableVpcClassicLink",
        "ec2:EnableVpcClassicLink",
        "ec2:GetConsoleScreenshot",
        "ec2:RebootInstances",
        "ec2:RejectVpcPeeringConnection",
        "ec2:RevokeSecurityGroupEgress",
        "ec2:RevokeSecurityGroupIngress",
        "ec2:RunInstances",
        "ec2:StartInstances",
        "ec2:StopInstances",
        "ec2:TerminateInstances"
      ],
      "Effect": "Allow",
      "Resource": [
        "*"
      ]
    },
    {
      "Action": "s3:*",
      "Effect": "Allow",
      "Resource": [
        "*"
      ]
    },
    {
      "Action": [
        "iam:GetAccessKeyLastUsed",
        "iam:GetGroup*",
        "iam:GetInstanceProfile",
        "iam:GetLoginProfile",
        "iam:GetOpenIDConnectProvider",
        "iam:GetPolicy*",
        "iam:GetRole*",
        "iam:GetSAMLProvider",
        "iam:GetSSHPublicKey",
        "iam:GetServerCertificate",
        "iam:GetServiceLastAccessed*",
        "iam:GetUser*",
        "iam:ListAccessKeys",
        "iam:ListAttached*",
        "iam:ListEntitiesForPolicy",
        "iam:ListGroupPolicies",
        "iam:ListGroupsForUser",
        "iam:ListInstanceProfiles*",
        "iam:ListMFADevices",
        "iam:ListPolicyVersions",
        "iam:ListRolePolicies",
        "iam:ListSSHPublicKeys",
        "iam:ListSigningCertificates",
        "iam:ListUserPolicies",
        "iam:Upload*"
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
	a, err := NewAwsPolicyParser(policyText, false)
	require.NoError(t, err)
	a.Trace = true
	err = a.Parse()
	require.NoError(t, err)

	policies, err := a.GetPolicy()
	require.NoError(t, err)

	for index, pol := range policies {
		log.Infof("pol #%d: %+v", index, pol)
	}

	require.Len(t, policies, 5)
	require.Len(t, policies[0].Condition, 0)
}

func Test_recursiveUnescape(t *testing.T) {
	type args struct {
		policyText string
	}
	tests := []struct {
		name  string
		args  args
		want  string
		errFn require.ErrorAssertionFunc
	}{
		{
			name: "not escaped",
			args: args{
				policyText: "something",
			},
			want:  "something",
			errFn: require.NoError,
		},
		{
			name: "not escaped bad input",
			args: args{
				policyText: "hello%",
			},
			want:  "hello%",
			errFn: require.Error,
		},
		{
			name: "escaped once",
			args: args{
				policyText: url.QueryEscape("something"),
			},
			want:  "something",
			errFn: require.NoError,
		},
		{
			name: "escaped twice",
			args: args{
				policyText: url.QueryEscape(url.QueryEscape("something")),
			},
			want:  "something",
			errFn: require.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := recursiveUnescape(tt.args.policyText)
			tt.errFn(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
