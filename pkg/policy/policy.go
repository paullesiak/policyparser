package policy

type Policy struct {
	Id           string      `json:"id" yaml:"id"`                       // policy Id
	Version      string      `json:"version" yaml:"version"`             // policy Version
	Subjects     []string    `json:"subjects" yaml:"subjects"`           // list of subjects included
	NotSubjects  []string    `json:"not-subjects" yaml:"not-subjects"`   // list of subjects excluded
	Resources    []string    `json:"resources" yaml:"resources"`         // list of resources included
	NotResources []string    `json:"not-resources" yaml:"not-resources"` // list of resources excluded
	Actions      []string    `json:"actions" yaml:"actions"`             // list of actions included
	NotActions   []string    `json:"not-actions" yaml:"not-actions"`     // list of actions excluded
	Allowed      bool        `json:"allowed" yaml:"allowed"`             // effect of a policy match
	Condition    []Condition `json:"conditions" yaml:"conditions"`       // map key is the operator
}

type Condition struct {
	Operation string        `json:"operator" yaml:"operator"`     // condition operator
	Key       []string      `json:"key" yaml:"key"`               // name of the parameter that should match the value
	Value     []interface{} `json:"values" yaml:"values"`         // is a list of either string, int64 or bool
	Type      []string      `json:"value-type" yaml:"value-type"` // string, int64, bool
}
