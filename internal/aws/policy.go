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
	Block *Block `parser:"'{' @@ '}'"`
}

type BlockValue interface{ value() }

type BlockString struct {
	String string `parser:"@String"`
}

func (BlockString) value() {}

type BlockStatement struct {
	Statement []*Statement `parser:"'[' '{' @@ '}' ((',' '{' @@ '}')*)? ']'"`
}

func (BlockStatement) value() {}

type BlockProperty struct {
	Key   string     `parser:"@String ':'"`
	Value BlockValue `parser:"@@"`
}

type Block struct {
	Properties  []*BlockProperty `parser:"@@ ((',' @@)*)?"`
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
	Elements []*Elements `parser:"@@ (',' @@)*"`
}

type Elements struct {
	Sid          *string    `parser:"'Sid' ':' @String"`
	Effect       *string    `parser:"| 'Effect' ':' @String"`
	Principal    *Principal `parser:"| 'Principal' ':' @@"`
	NotPrincipal *Principal `parser:"| 'NotPrincipal' ':' @@"`
	Action       *AnyOrList `parser:"| 'Action' ':' @@"`
	NotAction    *AnyOrList `parser:"| 'NotAction' ':' @@"`
	Resource     *AnyOrList `parser:"| 'Resource' ':' @@"`
	NotResource  *AnyOrList `parser:"| 'NotResource' ':' @@"`
	Condition    *Condition `parser:"| 'Condition' ':' @@"`
}

type AnyOrList struct {
	Item *Item   `parser:"@@"`
	List []*Item `parser:"| '[' @@ ((',' @@)*)? ']'"`
}

type Item struct {
	Any bool    `parser:"@'*'"`
	One *string `parser:"| @String"`
}

type Principal struct {
	Any  bool             `parser:"@'*'"`
	List []*PrincipalList `parser:"| '{' @@ ((',' @@)*)? '}'"`
}

type PrincipalList struct {
	Aws       *AnyOrList `parser:"'AWS' ':' @@"`
	Federated *AnyOrList `parser:"| 'Federated' ':' @@"`
	Canonical *AnyOrList `parser:"| 'CanonicalUser' ':' @@"`
	Service   *AnyOrList `parser:"| 'Service' ':' @@"`
}

type Condition struct {
	ConditionList []*ConditionList `parser:"'{' @@ ((',' @@)*)? '}'"`
}

type ConditionList struct {
	Operation    *string         `parser:"@String ':'"`
	KeyValueList []*KeyValueList `parser:"'{' @@ ((',' @@)*)? '}'"`
}

type KeyValueList struct {
	Key   *string    `parser:"@String ':'"`
	Value *ValueList `parser:"@@"`
}

type ValueList struct {
	One  *Value   `parser:"@@"`
	List []*Value `parser:"| '[' @@ ((',' @@)*)? ']'"`
}

type Value struct {
	OneString *string `parser:"@String"`
	OneNumber *int64  `parser:"| @Int"`
	BoolTrue  *bool   `parser:"| @'true'"`
	BoolFalse *bool   `parser:"| @'false'"`
}
