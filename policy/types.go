package policy

// Document describes a collection of policies that can be serialized as JSON or YAML.
type Document struct {
	Version       string   `json:"version,omitempty" yaml:"version,omitempty"`
	DefaultEffect *Effect  `json:"default_effect,omitempty" yaml:"default_effect,omitempty"`
	Policies      []Policy `json:"policies" yaml:"policies"`
}

// Policy groups a list of rules under a logical name.
type Policy struct {
	Name          string   `json:"name" yaml:"name"`
	Description   string   `json:"description,omitempty" yaml:"description,omitempty"`
	DefaultEffect *Effect  `json:"default_effect,omitempty" yaml:"default_effect,omitempty"`
	Rules         []Rule   `json:"rules" yaml:"rules"`
	Tags          []string `json:"tags,omitempty" yaml:"tags,omitempty"`
}

// Rule contains a single expression condition paired with an outcome.
type Rule struct {
	ID          string            `json:"id,omitempty" yaml:"id,omitempty"`
	Description string            `json:"description,omitempty" yaml:"description,omitempty"`
	Effect      Effect            `json:"effect" yaml:"effect"`
	Condition   string            `json:"condition" yaml:"condition"`
	Metadata    map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
}

// Decision captures the result of evaluating a policy set.
type Decision struct {
	Effect       Effect `json:"effect"`
	Policy       string `json:"policy,omitempty"`
	Rule         string `json:"rule,omitempty"`
	Message      string `json:"message,omitempty"`
	Matched      bool   `json:"matched"`
	Evaluated    int    `json:"evaluated_rules"`
	Error        error  `json:"error"`
	ErrorMessage string `json:"error_message,omitempty"`
}
