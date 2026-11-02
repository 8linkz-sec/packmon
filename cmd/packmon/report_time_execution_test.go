package main

import (
	"encoding/base64"
	"os/exec"
	"strings"
	"testing"
)

func TestGeneratedHTMLReportLocaleScriptExecutesFormattingContracts(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required to execute the generated report locale script")
	}

	const prefix = "<script>\n"
	const suffix = "\n</script>"
	body, ok := strings.CutPrefix(generatedHTMLReportLocaleScript, prefix)
	if !ok {
		t.Fatalf("locale script missing exact %q wrapper", prefix)
	}
	body, ok = strings.CutSuffix(body, suffix)
	if !ok {
		t.Fatalf("locale script missing exact %q wrapper", suffix)
	}
	if prefix+body+suffix != generatedHTMLReportLocaleScript {
		t.Fatal("extracted locale script body is not byte-identical to the production constant")
	}

	encoded := base64.StdEncoding.EncodeToString([]byte(body))
	cmd := exec.Command(node, "-e", reportLocaleNodeHarness, encoded)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("execute locale script with Node: %v\n%s", err, output)
	}
	if got := strings.TrimSpace(string(output)); got != "ok" {
		t.Fatalf("locale script harness output = %q, want ok", got)
	}
}

const reportLocaleNodeHarness = `
const vm = require('vm');
const source = Buffer.from(process.argv[1], 'base64').toString('utf8');
const RealIntl = Intl;

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function makeNode(attributes, text) {
  return {
    attributes: Object.assign({}, attributes),
    textContent: text,
    getAttribute(name) {
      return Object.prototype.hasOwnProperty.call(this.attributes, name) ? this.attributes[name] : null;
    },
    hasAttribute(name) {
      return Object.prototype.hasOwnProperty.call(this.attributes, name);
    },
    setAttribute(name, value) {
      this.attributes[name] = String(value);
    }
  };
}

function execute(options) {
  const dateCalls = [];
  const numberCalls = [];
  const times = options.times || [];
  const durations = options.durations || [];
  const document = {
    documentElement: {
      getAttribute(name) {
        assert(name === 'lang', 'unexpected documentElement attribute: ' + name);
        return options.lang || '';
      }
    },
    querySelectorAll(selector) {
      if (selector === 'time[data-report-time][datetime]') return times;
      if (selector === '[data-report-duration][data-duration-ms]') return durations;
      throw new Error('unexpected selector: ' + selector);
    }
  };
  let wrappedIntl;
  if (options.withIntl !== false) {
    wrappedIntl = {
      DateTimeFormat: function(locales, formatOptions) {
        dateCalls.push({locales: locales, options: Object.assign({}, formatOptions)});
        return new RealIntl.DateTimeFormat(locales, formatOptions);
      },
      NumberFormat: function(locales, formatOptions) {
        numberCalls.push({locales: locales, options: Object.assign({}, formatOptions)});
        return new RealIntl.NumberFormat(locales, formatOptions);
      }
    };
  }
  vm.runInNewContext(source, {
    navigator: {languages: options.languages, language: options.language},
    document: document,
    Intl: wrappedIntl,
    Date: Date,
    Number: Number,
    isNaN: isNaN,
    isFinite: isFinite
  });
  return {dateCalls, numberCalls, times, durations};
}

const validTime = makeNode({datetime: '2026-09-14T08:30:00Z'}, '2026-09-14 08:30 UTC');
const missingTime = makeNode({datetime: ''}, 'missing fallback');
const invalidTime = makeNode({datetime: 'not-a-date'}, 'invalid fallback');
const duration999 = makeNode({'data-duration-ms': '999'}, '999 fallback');
const duration1000 = makeNode({'data-duration-ms': '1000'}, '1000 fallback');
const duration10000 = makeNode({'data-duration-ms': '10000'}, '10000 fallback');
const ignoredDurations = [
  makeNode({'data-duration-ms': '0'}, 'zero fallback'),
  makeNode({'data-duration-ms': '-1'}, 'negative fallback'),
  makeNode({'data-duration-ms': 'NaN'}, 'nan fallback'),
  makeNode({'data-duration-ms': 'Infinity'}, 'infinite fallback'),
  makeNode({}, 'missing fallback')
];
const locales = ['en-US', 'de-DE'];
const result = execute({
  languages: locales,
  language: 'fr-FR',
  lang: 'es-ES',
  times: [validTime, missingTime, invalidTime],
  durations: [duration999, duration1000, duration10000].concat(ignoredDurations)
});

assert(result.dateCalls.length === 1, 'expected one DateTimeFormat call');
assert(JSON.stringify(result.dateCalls[0].locales) === JSON.stringify(locales), 'navigator.languages was not used');
const expectedDateOptions = {year:'numeric', month:'short', day:'numeric', hour:'numeric', minute:'2-digit', timeZoneName:'short'};
assert(JSON.stringify(result.dateCalls[0].options) === JSON.stringify(expectedDateOptions), 'unexpected DateTimeFormat options: ' + JSON.stringify(result.dateCalls[0].options));
const expectedTime = new RealIntl.DateTimeFormat(locales, expectedDateOptions).format(new Date('2026-09-14T08:30:00Z'));
assert(validTime.textContent === expectedTime, 'valid timestamp was not formatted by the real Intl implementation');
assert(validTime.attributes['data-fallback-text'] === '2026-09-14 08:30 UTC', 'timestamp fallback was not retained');
assert(missingTime.textContent === 'missing fallback' && !missingTime.hasAttribute('data-fallback-text'), 'missing timestamp changed');
assert(invalidTime.textContent === 'invalid fallback' && !invalidTime.hasAttribute('data-fallback-text'), 'invalid timestamp changed');

assert(result.numberCalls.length === 3, 'expected exactly three NumberFormat calls');
const durationCases = [
  {node: duration999, value: 999, unit: 'ms', digits: 0, fallback: '999 fallback'},
  {node: duration1000, value: 1, unit: 's', digits: 1, fallback: '1000 fallback'},
  {node: duration10000, value: 10, unit: 's', digits: 0, fallback: '10000 fallback'}
];
durationCases.forEach(function(entry, index) {
  const call = result.numberCalls[index];
  assert(JSON.stringify(call.locales) === JSON.stringify(locales), 'unexpected duration locales at index ' + index);
  assert(JSON.stringify(call.options) === JSON.stringify({maximumFractionDigits: entry.digits}), 'unexpected duration options at index ' + index);
  const expected = new RealIntl.NumberFormat(locales, {maximumFractionDigits: entry.digits}).format(entry.value) + ' ' + entry.unit;
  assert(entry.node.textContent === expected, 'unexpected duration text at index ' + index + ': ' + entry.node.textContent);
  assert(entry.node.attributes['data-fallback-text'] === entry.fallback, 'duration fallback was not retained at index ' + index);
});
ignoredDurations.forEach(function(node) {
  assert(!node.hasAttribute('data-fallback-text'), 'nonpositive/nonfinite duration received fallback metadata');
  assert(node.textContent.endsWith('fallback'), 'nonpositive/nonfinite duration text changed');
});

const languageFallback = execute({languages: [], language: 'fr-FR', lang: 'es-ES'});
assert(languageFallback.dateCalls[0].locales === 'fr-FR', 'navigator.language fallback was not used');
const htmlFallback = execute({languages: [], language: '', lang: 'es-ES'});
assert(htmlFallback.dateCalls[0].locales === 'es-ES', 'document lang fallback was not used');
const undefinedFallback = execute({languages: [], language: '', lang: ''});
assert(undefinedFallback.dateCalls[0].locales === undefined, 'missing locale did not pass explicit undefined');

const noIntlTime = makeNode({datetime: '2026-09-14T08:30:00Z'}, 'time fallback');
const noIntlDuration = makeNode({'data-duration-ms': '1000'}, 'duration fallback');
const noIntl = execute({withIntl: false, times: [noIntlTime], durations: [noIntlDuration]});
assert(noIntl.dateCalls.length === 0 && noIntl.numberCalls.length === 0, 'missing Intl unexpectedly constructed formatters');
assert(noIntlTime.textContent === 'time fallback' && !noIntlTime.hasAttribute('data-fallback-text'), 'missing Intl changed timestamp');
assert(noIntlDuration.textContent === 'duration fallback' && !noIntlDuration.hasAttribute('data-fallback-text'), 'missing Intl changed duration');

process.stdout.write('ok');
`
