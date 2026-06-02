package dockerimage

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

func ParseDockerfileImages(r io.Reader, sourceFile string) ([]Image, error) {
	scanner := bufio.NewScanner(r)
	args := make(map[string]string)
	stages := make(map[string]struct{})
	var images []Image
	lineNo := 0

	for scanner.Scan() {
		lineNo++
		line := stripDockerfileComment(strings.TrimSpace(scanner.Text()))
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch strings.ToUpper(fields[0]) {
		case "ARG":
			name, value, ok := parseDockerArg(strings.TrimSpace(strings.TrimPrefix(line, fields[0])))
			if ok && value != "" {
				args[name] = value
			}
		case "FROM":
			fromFields := dockerfileFromFields(fields[1:])
			if len(fromFields) == 0 {
				return nil, fmt.Errorf("%s:%d: FROM without image", sourceFile, lineNo)
			}
			raw := substituteDockerArgs(fromFields[0], args)
			alias := dockerfileStageAlias(fromFields)
			if _, ok := stages[strings.ToLower(raw)]; ok {
				if alias != "" {
					stages[strings.ToLower(alias)] = struct{}{}
				}
				continue
			}
			ref, ok := ParseRef(raw)
			if !ok {
				if strings.EqualFold(raw, "scratch") {
					if alias != "" {
						stages[strings.ToLower(alias)] = struct{}{}
					}
					continue
				}
				return nil, fmt.Errorf("%s:%d: invalid FROM image %q", sourceFile, lineNo, raw)
			}
			if alias != "" {
				stages[strings.ToLower(alias)] = struct{}{}
			}
			images = append(images, Image{
				Ref:        ref,
				SourceFile: sourceFile,
				SourceType: SourceDockerfile,
				Scope:      "runtime",
				Relation:   "base",
				Direct:     true,
				Flags:      dockerfileFlags(fromFields),
			})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("%s: read Dockerfile: %w", sourceFile, err)
	}
	for i := range images {
		if i == 0 && len(images) > 1 {
			images[i].Scope = "build"
		}
	}
	return images, nil
}

func stripDockerfileComment(line string) string {
	if idx := strings.Index(line, "#"); idx >= 0 {
		return strings.TrimSpace(line[:idx])
	}
	return line
}

func parseDockerArg(raw string) (string, string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", false
	}
	parts := strings.SplitN(raw, "=", 2)
	name := strings.TrimSpace(parts[0])
	if name == "" {
		return "", "", false
	}
	if len(parts) == 1 {
		return name, "", true
	}
	return name, strings.TrimSpace(parts[1]), true
}

func substituteDockerArgs(raw string, args map[string]string) string {
	for name, value := range args {
		raw = strings.ReplaceAll(raw, "${"+name+"}", value)
		raw = strings.ReplaceAll(raw, "$"+name, value)
	}
	return raw
}

func dockerfileFlags(fields []string) []string {
	alias := dockerfileStageAlias(fields)
	if alias != "" {
		return []string{"stage=" + alias}
	}
	return nil
}

func dockerfileStageAlias(fields []string) string {
	for i := 1; i+1 < len(fields); i++ {
		if strings.EqualFold(fields[i], "AS") {
			return fields[i+1]
		}
	}
	return ""
}

func dockerfileFromFields(fields []string) []string {
	for len(fields) > 0 && strings.HasPrefix(fields[0], "--") {
		fields = fields[1:]
	}
	return fields
}
