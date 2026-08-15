package parser

import "go.yaml.in/yaml/v3"

// yamlUnmarshal is a thin wrapper so that only this file imports the yaml
// package directly.
func yamlUnmarshal(data []byte, v interface{}) error {
	return yaml.Unmarshal(data, v)
}

// yamlNode is the parsed YAML document tree, exposed for parsers that need
// node-level metadata (such as line comments) in addition to typed decoding.
type yamlNode = yaml.Node

// yamlNodeKind values used by node-walking parsers.
const (
	yamlDocumentNode = yaml.DocumentNode
	yamlMappingNode  = yaml.MappingNode
	yamlSequenceNode = yaml.SequenceNode
	yamlScalarNode   = yaml.ScalarNode
)

// yamlUnmarshalNode parses data into a YAML node tree.
func yamlUnmarshalNode(data []byte, node *yaml.Node) error {
	return yaml.Unmarshal(data, node)
}
