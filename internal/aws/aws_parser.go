package aws

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/alecthomas/participle/v2"
	log "github.com/sirupsen/logrus"

	"github.com/paullesiak/policyparser/pkg/policy"
)

type AwsParser struct {
	policyText string
	awsPolicy  *AwsPolicy
	policies   []*policy.Policy
	parsed     bool
	error      error
	Trace      bool
}

// recursiveUnescape will repeatedly attempt to unescape the string until the input is equal to the unescaped output.
// This is because for some reason, AWS sometimes double encodes values.
func recursiveUnescape(policyText string) (string, error) {
	pt, err := url.QueryUnescape(policyText)
	if err != nil {
		return policyText, err
	}
	if pt == policyText {
		return pt, nil
	}
	return recursiveUnescape(pt)
}

func NewAwsPolicyParser(policyText string, escaped bool) (*AwsParser, error) {
	var err error
	pt := policyText
	if escaped {
		pt, err = recursiveUnescape(policyText)
		if err != nil {
			return nil, fmt.Errorf("error unescaping policy text: %w", err)
		}
	}
	// log.Debugf("/n%s", pt)
	return &AwsParser{
		policyText: pt,
		awsPolicy:  &AwsPolicy{},
		parsed:     false,
		error:      nil,
	}, nil
}

func (a *AwsParser) Parse() error {
	parser, err := participle.Build[AwsPolicy](
		participle.UseLookahead(2),
	)
	if err != nil {
		return fmt.Errorf("error building parser: %w", err)
	}
	opts := []participle.ParseOption{participle.AllowTrailing(true)}
	if a.Trace {
		opts = append(opts /*participle.Trace(os.Stdout)*/)
	}
	ast, err := parser.ParseString("", a.policyText, opts...)

	if err == nil {
		a.parsed = true
		a.constructPolicy(ast)
	} else {
		var p *participle.UnexpectedTokenError
		if errors.As(err, &p) {
			log.Errorf("Error parsing policy: %s : %s", p.Error(), p.Unexpected.Pos.String())
			a.error = err
		}
	}
	return err
}

func (a *AwsParser) GetPolicy() ([]*policy.Policy, error) {
	if a.parsed {
		return a.policies, nil
	}
	if a.error != nil {
		return nil, a.error
	}
	return nil, fmt.Errorf("did not parse")
}

func (a *AwsParser) Json() ([]byte, error) {
	if a.parsed && a.policies != nil {
		return json.Marshal(a.policies)
	}
	return nil, fmt.Errorf("no policies parsed yet")
}

func (a *AwsParser) WriteJson(filename string) error {
	if a.parsed && a.policies != nil {
		if _, err := os.Stat(filename); err == nil {
			return fmt.Errorf("File exists: %s", filename)
		}
		f, err := os.OpenFile(filename, os.O_CREATE|os.O_RDWR, 0666)
		if err != nil {
			return err
		}
		defer f.Close()
		enc := json.NewEncoder(f)
		enc.SetEscapeHTML(false)
		return enc.Encode(a.policies)
	}
	return fmt.Errorf("no policies parsed yet")
}

func (a *AwsParser) constructPolicy(ast *AwsPolicy) {
	if a.awsPolicy == nil {
		return
	}

	a.policies = []*policy.Policy{}

	id := StringValue(ast.Block.Id)
	version := StringValue(ast.Block.Version)

	for index, statement := range ast.Block.Statement {
		pol := &policy.Policy{
			Id:      fmt.Sprintf("%s:%d", id, index),
			Version: version,
		}

		for _, element := range statement.Elements {
			if element.Effect != nil {
				effect := StringValue(element.Effect)
				switch strings.ToLower(effect) {
				case "allow":
					pol.Allowed = true
				default:
					pol.Allowed = false
				}
			}
			if element.Action != nil {
				pol.Actions = a.getAnyOrList(element.Action)
			}
			if element.NotAction != nil {
				pol.NotActions = a.getAnyOrList(element.NotAction)
			}
			if element.Resource != nil {
				pol.Resources = a.getAnyOrList(element.Resource)
			}
			if element.NotResource != nil {
				pol.NotResources = a.getAnyOrList(element.NotResource)
			}
			if element.Principal != nil {
				pol.Subjects = a.getSubjects(element.Principal)
			}
			if element.NotPrincipal != nil {
				pol.NotSubjects = a.getSubjects(element.NotPrincipal)
			}
			if element.Condition != nil {
				pol.Condition = a.getCondition(element.Condition)
			}
		}

		a.policies = append(a.policies, pol)
	}
}

func (a *AwsParser) getAnyOrList(l *AnyOrList) []string {
	if l == nil {
		return []string{}
	}
	if l.Item != nil {
		if l.Item.Any {
			return []string{"<.*>"}
		}
		if l.Item.One != nil {
			vs := StringValue(l.Item.One)
			return []string{strings.ReplaceAll(vs, "*", "<.*>")}
		}
	}
	if l.List != nil {
		x := []string{}
		for _, item := range l.List {
			if item.Any {
				x = append(x, "<.*>")
			}
			if item.One != nil {
				vs := StringValue(item.One)
				x = append(x, strings.ReplaceAll(vs, "*", "<.*>"))
			}
		}
		return x
	}
	return []string{}
}

func (a *AwsParser) getSubjects(p *Principal) []string {
	if p == nil {
		return []string{}
	}
	if p.Any {
		return []string{"<.*>"}
	}
	x := []string{}
	if p.List != nil {
		for _, item := range p.List {
			if item.Aws != nil {
				x = append(x, a.getAnyOrList(item.Aws)...)
			}
			if item.Federated != nil {
				x = append(x, a.getAnyOrList(item.Federated)...)
			}
			if item.Canonical != nil {
				x = append(x, a.getAnyOrList(item.Canonical)...)
			}
			if item.Service != nil {
				x = append(x, a.getAnyOrList(item.Service)...)
			}
		}
	}

	return x
}

func (a *AwsParser) getCondition(c *Condition) []policy.Condition {
	if c == nil {
		return nil
	}

	var cm []policy.Condition

	for _, cc := range c.ConditionList {
		op := StringValue(cc.Operation)
		if op == "" {
			continue
		}
		if cc.KeyValueList == nil {
			continue
		}
		var values []any
		var keys []string
		var valTypes []string
		for _, kvList := range cc.KeyValueList {
			ck := StringValue(kvList.Key)
			if ck == "" {
				continue
			}
			valType := ""
			var val any
			if kvList.Value == nil {
				continue
			}
			switch {
			case kvList.Value.One != nil:
				if kvList.Value.One.OneString != nil {
					val = []string{StringValue(kvList.Value.One.OneString)}
					valType = "string"
				}
				if kvList.Value.One.OneNumber != nil {
					val = []int64{Int64Value(kvList.Value.One.OneNumber)}
					valType = "int64"
				}
				if kvList.Value.One.BoolTrue != nil {
					val = []bool{true}
					valType = "bool"
				}
				if kvList.Value.One.BoolFalse != nil {
					val = []bool{false}
					valType = "bool"
				}
			case kvList.Value.List != nil:
				valType = ""
				mixedTypes := false
				var sl []string
				var il []int64
				var bl []bool
				for _, v := range kvList.Value.List {
					ctype := ""
					if v.OneString != nil {
						sl = append(sl, StringValue(v.OneString))
						ctype = "string"
					}
					if v.OneNumber != nil {
						il = append(il, Int64Value(v.OneNumber))
						ctype = "int64"
					}
					if v.BoolTrue != nil {
						bl = append(bl, true)
						ctype = "bool"
					}
					if v.BoolFalse != nil {
						bl = append(bl, false)
						ctype = "bool"
					}
					if valType == "" {
						valType = ctype
					}
					if valType != ctype {
						mixedTypes = true
						break
					}
				}
				if mixedTypes {
					continue
				}
				switch valType {
				case "string":
					val = sl
				case "int64":
					val = il
				case "bool":
					val = bl
				}
			}
			values = append(values, val)
			keys = append(keys, ck)
			valTypes = append(valTypes, valType)
		}
		cp := policy.Condition{
			Operation: op,
			Key:       keys,
			Value:     values,
			Type:      valTypes,
		}

		cm = append(cm, cp)
	}

	return cm
}
