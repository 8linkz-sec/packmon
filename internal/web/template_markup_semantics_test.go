package web

import (
	"bufio"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/net/html"
)

// These tests read the template sources the way the SonarQube HTML analyzer
// does (an HTML tokenizer that knows nothing about Go template actions), so a
// template that passes them also passes Web:S6811, Web:S6819 and Web:S7927,
// and the scrollable-region exception for Web:S6845 stays limited to the
// files listed in sonar-project.properties.

type templateTag struct {
	file  string
	line  int
	name  string
	attrs map[string]string
}

type templateText struct {
	file   string
	line   int
	parent *templateTag
	text   string
}

type templateMarkup struct {
	tags  []*templateTag
	texts []templateText
}

var templateVoidElements = map[string]bool{
	"area": true, "base": true, "br": true, "col": true, "embed": true, "hr": true, "img": true,
	"input": true, "link": true, "meta": true, "source": true, "track": true, "wbr": true,
}

func scanTemplateMarkup(t *testing.T) templateMarkup {
	t.Helper()

	var markup templateMarkup
	err := fs.WalkDir(os.DirFS("templates"), ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || path.Ext(name) != ".html" {
			return nil
		}
		source := readTextFile(t, "templates", name)
		scanTemplateFile(path.Join("internal/web/templates", name), source, &markup)
		return nil
	})
	if err != nil {
		t.Fatalf("walk templates: %v", err)
	}
	return markup
}

func scanTemplateFile(file, source string, markup *templateMarkup) {
	tokenizer := html.NewTokenizer(strings.NewReader(source))
	line := 1
	var open []*templateTag
	for {
		kind := tokenizer.Next()
		if kind == html.ErrorToken {
			return
		}
		raw := string(tokenizer.Raw())
		token := tokenizer.Token()
		switch kind {
		case html.StartTagToken, html.SelfClosingTagToken:
			tag := &templateTag{file: file, line: line, name: token.Data, attrs: map[string]string{}}
			for _, attr := range token.Attr {
				tag.attrs[attr.Key] = attr.Val
			}
			markup.tags = append(markup.tags, tag)
			if kind == html.StartTagToken && !templateVoidElements[tag.name] {
				open = append(open, tag)
			}
		case html.EndTagToken:
			for i := len(open) - 1; i >= 0; i-- {
				if open[i].name == token.Data {
					open = open[:i]
					break
				}
			}
		case html.TextToken:
			if len(open) > 0 && strings.TrimSpace(token.Data) != "" {
				markup.texts = append(markup.texts, templateText{file: file, line: line, parent: open[len(open)-1], text: token.Data})
			}
		}
		line += strings.Count(raw, "\n")
	}
}

func normalizeAccessibleText(text string) string {
	return strings.Join(strings.Fields(strings.ToLower(text)), " ")
}

// Mirrors Web:S7927: an aria-label on a button, link, select, textarea or
// role="button" element must contain each of its visible direct text nodes.
// Composing the aria-label from the same {{t ...}} action as the visible label
// keeps the rendered accessible name and the visible label in step.
func TestTemplateAriaLabelsContainTheirVisibleLabel(t *testing.T) {
	t.Parallel()

	labelled := map[string]bool{"a": true, "button": true, "select": true, "textarea": true}
	var violations []string
	for _, text := range scanTemplateMarkup(t).texts {
		parent := text.parent
		if !labelled[parent.name] && !strings.EqualFold(parent.attrs["role"], "button") {
			continue
		}
		ariaLabel := strings.TrimSpace(parent.attrs["aria-label"])
		visible := normalizeAccessibleText(text.text)
		if ariaLabel == "" || len(strings.Fields(visible)) == 1 {
			continue
		}
		if !strings.Contains(normalizeAccessibleText(ariaLabel), visible) {
			violations = append(violations, parent.file+":"+strconv.Itoa(parent.line)+" <"+parent.name+"> aria-label "+strconv.Quote(ariaLabel)+" lacks visible text "+strconv.Quote(visible))
		}
	}
	if len(violations) > 0 {
		t.Fatalf("aria-label must contain the visible label:\n%s", strings.Join(violations, "\n"))
	}
}

// Mirrors Web:S6819 for the roles the templates used: landmarks, live status
// text and control groups use the native element that carries the role.
func TestTemplatesUseNativeElementsInsteadOfRegionStatusAndGroupRoles(t *testing.T) {
	t.Parallel()

	native := map[string]string{"region": "section", "status": "output", "group": "fieldset"}
	var violations []string
	for _, tag := range scanTemplateMarkup(t).tags {
		role := strings.ToLower(strings.TrimSpace(tag.attrs["role"]))
		if element, ok := native[role]; ok {
			violations = append(violations, tag.file+":"+strconv.Itoa(tag.line)+" <"+tag.name+` role="`+role+`"> should be <`+element+">")
		}
	}
	if len(violations) > 0 {
		t.Fatalf("templates use ARIA roles that have a native element:\n%s", strings.Join(violations, "\n"))
	}
}

// Mirrors Web:S6811 for status text: aria-disabled is not supported on the
// status role, so it must not appear on <output> or role="status" elements.
func TestTemplateStatusElementsCarryNoAriaDisabled(t *testing.T) {
	t.Parallel()

	var violations []string
	for _, tag := range scanTemplateMarkup(t).tags {
		isStatus := tag.name == "output" || strings.EqualFold(strings.TrimSpace(tag.attrs["role"]), "status")
		if _, ok := tag.attrs["aria-disabled"]; ok && isStatus {
			violations = append(violations, tag.file+":"+strconv.Itoa(tag.line)+" <"+tag.name+">")
		}
	}
	if len(violations) > 0 {
		t.Fatalf("aria-disabled on status elements:\n%s", strings.Join(violations, "\n"))
	}
}

// The no-op bulk queue actions render in place of a button and keep the
// generic disabled look through their own style hook instead of aria-disabled.
func TestUnavailableActionPlaceholderKeepsTheDisabledLook(t *testing.T) {
	t.Parallel()

	styleCSS := readTextFile(t, "static", "style.css")
	for _, rule := range []string{"cursor: not-allowed;\n  opacity: 0.6;", "pointer-events: none;"} {
		index := strings.Index(styleCSS, rule)
		if index < 0 {
			t.Fatalf("style.css lost disabled rule %q", rule)
		}
		selectors := styleCSS[strings.LastIndex(styleCSS[:index], "}")+1 : index]
		if !strings.Contains(selectors, "[data-unavailable-action]") {
			t.Fatalf("disabled rule %q does not cover [data-unavailable-action]; selectors:\n%s", rule, selectors)
		}
	}
	queue := readTextFile(t, "templates", "admin", "queue.html")
	if got := strings.Count(queue, "data-unavailable-action"); got != 2 {
		t.Fatalf("admin queue unavailable-action placeholders = %d, want 2 (purge and clear)", got)
	}
}

// Sonar's interactive elements for Web:S6845 (HtmlConstants.INTERACTIVE_ELEMENTS).
var sonarInteractiveElements = map[string]bool{
	"a": true, "audio": true, "button": true, "canvas": true, "datalist": true, "embed": true, "input": true,
	"menuitem": true, "option": true, "select": true, "summary": true, "td": true, "textarea": true,
	"th": true, "tr": true, "video": true,
}

var scrollableRegionClass = regexp.MustCompile(`(^|\s)(pm-scroll-region|overflow-auto|overflow-x-auto|overflow-y-auto)(\s|$)`)

// Web:S6845 is accepted only for keyboard-focusable scrollable regions (DESIGN.md
// "Web UI": horizontally scrollable table regions must be keyboard-focusable,
// and the full error text in feed status must stay keyboard-reachable). This
// guard keeps every flagged site a scrollable region and keeps the exclusion
// in sonar-project.properties limited to exactly the files that contain one.
func TestFocusableNonInteractiveElementsAreScrollableRegionsListedInSonarExclusion(t *testing.T) {
	t.Parallel()

	regionFiles := map[string]bool{}
	var violations []string
	for _, tag := range scanTemplateMarkup(t).tags {
		value, ok := tag.attrs["tabindex"]
		if !ok || sonarInteractiveElements[tag.name] {
			continue
		}
		index, err := strconv.Atoi(value)
		if err != nil || index < 0 {
			continue
		}
		if !scrollableRegionClass.MatchString(tag.attrs["class"]) {
			violations = append(violations, tag.file+":"+strconv.Itoa(tag.line)+" <"+tag.name+` tabindex="`+value+`"> is not a scrollable region`)
			continue
		}
		regionFiles[tag.file] = true
	}
	if len(violations) > 0 {
		t.Fatalf("tabindex on non-interactive elements is accepted only for scrollable regions:\n%s", strings.Join(violations, "\n"))
	}

	excluded := sonarIgnoredResources(t, "Web:S6845")
	want := make([]string, 0, len(regionFiles))
	for file := range regionFiles {
		want = append(want, file)
	}
	slices.Sort(want)
	slices.Sort(excluded)
	if !slices.Equal(excluded, want) {
		t.Fatalf("sonar-project.properties Web:S6845 resources = %q, want exactly the scrollable-region files %q", excluded, want)
	}
}

// sonarIgnoredResources returns the resourceKey of every
// sonar.issue.ignore.multicriteria entry for ruleKey, and fails if the
// multicriteria list does not name exactly the defined entries.
func sonarIgnoredResources(t *testing.T, ruleKey string) []string {
	t.Helper()

	properties := readSonarProperties(t)
	const prefix = "sonar.issue.ignore.multicriteria"
	var ids []string
	for _, id := range strings.Split(properties[prefix], ",") {
		if id = strings.TrimSpace(id); id != "" {
			ids = append(ids, id)
		}
	}
	defined := 0
	for key := range properties {
		if strings.HasPrefix(key, prefix+".") && strings.HasSuffix(key, ".ruleKey") {
			defined++
		}
	}
	if defined != len(ids) {
		t.Fatalf("%s lists %d entries, but %d entries define a ruleKey", prefix, len(ids), defined)
	}
	var resources []string
	for _, id := range ids {
		rule := properties[prefix+"."+id+".ruleKey"]
		resource := properties[prefix+"."+id+".resourceKey"]
		if rule == "" || resource == "" {
			t.Fatalf("%s.%s needs both ruleKey and resourceKey", prefix, id)
		}
		if rule == ruleKey {
			resources = append(resources, resource)
		}
	}
	return resources
}

func readSonarProperties(t *testing.T) map[string]string {
	t.Helper()

	file, err := os.Open("../../sonar-project.properties")
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]string{}
	}
	if err != nil {
		t.Fatalf("open sonar-project.properties: %v", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			t.Errorf("close sonar-project.properties: %v", closeErr)
		}
	}()
	return parseSonarProperties(t, file)
}

func parseSonarProperties(t *testing.T, reader io.Reader) map[string]string {
	t.Helper()

	properties := map[string]string{}
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("sonar-project.properties line without '=': %q", line)
		}
		properties[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read sonar-project.properties: %v", err)
	}
	return properties
}
