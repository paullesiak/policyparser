package aws

/*
	Policy Grammar for AWS: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html

awsPolicy  = {
     <version_block?>
     <id_block?>
     <statement_block>
}

<version_block> = "Version" : ("2008-10-17" | "2012-10-17")

<id_block> = "Id" : <policy_id_string>

<statement_block> = "Statement" : [ <statement>, <statement>, ... ]

<statement> = {
    <sid_block?>,
    <principal_block?>,
    <effect_block>,
    <action_block>,
    <resource_block>,
    <condition_block?>
}

<sid_block> = "Sid" : <sid_string>

<effect_block> = "Effect" : ("Allow" | "Deny")

<principal_block> = ("Principal" | "NotPrincipal") : ("*" | <principal_map>)

<principal_map> = { <principal_map_entry>, <principal_map_entry>, ... }

<principal_map_entry> = ("AWS" | "Federated" | "Service" | "CanonicalUser") :
    [<principal_id_string>, <principal_id_string>, ...]

<action_block> = ("Action" | "NotAction") :
    ("*" | [<action_string>, <action_string>, ...])

<resource_block> = ("Resource" | "NotResource") :
    ("*" | [<resource_string>, <resource_string>, ...])

<condition_block> = "Condition" : { <condition_map> }
<condition_map> = {
  <condition_type_string> : { <condition_key_string> : <condition_value_list> },
  <condition_type_string> : { <condition_key_string> : <condition_value_list> }, ...
}
<condition_value_list> = [<condition_value>, <condition_value>, ...]
<condition_value> = ("string" | "number" | "Boolean")

*/

type AwsPolicy struct {
	Block *Block `"{" @@ "}"`
}

type BlockValue interface{ value() }

type BlockString struct {
	String string `@String`
}

func (BlockString) value() {}

type BlockStatement struct {
	Statement []*Statement `"[" "{" @@ "}" ( ( "," "{" @@ "}" )* )? "]"`
}

func (BlockStatement) value() {}

type BlockProperty struct {
	Key   string     `@String ":"`
	Value BlockValue `@@`
}

type Block struct {
	Properties  []*BlockProperty `@@ (("," @@)*)?`
	propertyMap map[string]*BlockProperty
}

func (b *Block) populatePropertyMap() {
	b.propertyMap = make(map[string]*BlockProperty)
	for _, p := range b.Properties {
		b.propertyMap[p.Key] = p
	}
}
func (b *Block) GetProperty(key string) *BlockProperty {
	if b.propertyMap == nil {
		b.populatePropertyMap()
	}
	return b.propertyMap[key]
}

type Statement struct {
	Elements []*Elements `@@ ("," @@)*`
}

type Elements struct {
	Sid          *string    `"Sid" ":" @String`
	Effect       *string    `| "Effect" ":" @String`
	Principal    *Principal `| "Principal" ":" @@`
	NotPrincipal *Principal `| "NotPrincipal" ":" @@`
	Action       *AnyOrList `| "Action" ":" @@`
	NotAction    *AnyOrList `| "NotAction" ":" @@`
	Resource     *AnyOrList `| "Resource" ":" @@`
	NotResource  *AnyOrList `| "NotResource" ":" @@`
	Condition    *Condition `| "Condition" ":" @@`
}

type AnyOrList struct {
	Item *Item   `@@`
	List []*Item `| "[" @@ ( ( "," @@ )* )? "]"`
}

type Item struct {
	Any bool    `@("*")`
	One *string `| @String`
}

type Principal struct {
	Any  bool             `@("*")`
	List []*PrincipalList `| "{" @@ ( ("," @@ )* )? "}"`
}

type PrincipalList struct {
	Aws       *AnyOrList `"AWS" ":" @@`
	Federated *AnyOrList `| "Federated" ":" @@`
	Canonical *AnyOrList `| "CanonicalUser" ":" @@`
	Service   *AnyOrList `| "Service" ":" @@`
}

type Condition struct {
	ConditionList []*ConditionList `"{" @@ ( ( (",") @@ )* )? "}"`
}

type ConditionList struct {
	Operation    *string         `@String ":"`
	KeyValueList []*KeyValueList `"{" @@ ( ( "," @@)*)? "}"`
}

type KeyValueList struct {
	Key   *string    `@String ":"`
	Value *ValueList `@@`
}

type ValueList struct {
	One  *Value   `@@`
	List []*Value `| "[" @@ ( ("," @@ )* )? "]"`
}

type Value struct {
	OneString *string `@String`
	OneNumber *int64  `| @Int`
	BoolTrue  *bool   `| @"true"`
	BoolFalse *bool   `| @"false"`
}
