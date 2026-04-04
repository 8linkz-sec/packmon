package parser

import "gopkg.in/yaml.v3"

// yamlUnmarshal is a thin wrapper so that only this file imports the yaml
// package directly.
func yamlUnmarshal(data []byte, v interface{}) error {
	return yaml.Unmarshal(data, v)
}
