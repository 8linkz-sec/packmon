package feed

import "strings"

// ParseCVSSVector estimates a numeric CVSS base score from a CVSS 3.x or 2.0
// vector. Precise scores come from VulnCheck/NVD enrichment when available.
func ParseCVSSVector(vector string) float64 {
	if vector == "" {
		return 0
	}

	metrics := parseCVSSMetrics(vector)
	if isCVSSv2Vector(vector, metrics) {
		return parseCVSSv2Metrics(metrics)
	}
	return parseCVSSv3Metrics(metrics)
}

func parseCVSSMetrics(vector string) map[string]string {
	parts := strings.Split(vector, "/")
	metrics := make(map[string]string, len(parts))
	for _, part := range parts {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) == 2 {
			metrics[kv[0]] = kv[1]
		}
	}
	return metrics
}

func isCVSSv2Vector(vector string, metrics map[string]string) bool {
	if strings.HasPrefix(strings.TrimSpace(vector), "CVSS:2.") {
		return true
	}
	_, hasAuth := metrics["Au"]
	return hasAuth
}

func parseCVSSv3Metrics(metrics map[string]string) float64 {
	weights := map[string]map[string]float64{
		"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
		"AC": {"L": 0.77, "H": 0.44},
		"PR": {"N": 0.85, "L": 0.62, "H": 0.27},
		"UI": {"N": 0.85, "R": 0.62},
		"S":  {"C": 1.0, "U": 0.0},
		"C":  {"H": 0.56, "L": 0.22, "N": 0.0},
		"I":  {"H": 0.56, "L": 0.22, "N": 0.0},
		"A":  {"H": 0.56, "L": 0.22, "N": 0.0},
	}

	av := lookupWeight(metrics, weights, "AV", 0.55)
	ac := lookupWeight(metrics, weights, "AC", 0.44)
	pr := lookupWeight(metrics, weights, "PR", 0.62)
	ui := lookupWeight(metrics, weights, "UI", 0.62)
	exploitability := 8.22 * av * ac * pr * ui

	conf := lookupWeight(metrics, weights, "C", 0.0)
	integ := lookupWeight(metrics, weights, "I", 0.0)
	avail := lookupWeight(metrics, weights, "A", 0.0)
	iss := 1.0 - ((1.0 - conf) * (1.0 - integ) * (1.0 - avail))

	scopeChanged := metrics["S"] == "C"
	var impact float64
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}

	if impact <= 0 {
		return 0
	}

	var score float64
	if scopeChanged {
		score = 1.08 * (impact + exploitability)
	} else {
		score = impact + exploitability
	}

	if score > 10.0 {
		score = 10.0
	}
	if score < 0 {
		score = 0
	}

	return roundUp1(score)
}

func parseCVSSv2Metrics(metrics map[string]string) float64 {
	weights := map[string]map[string]float64{
		"AV": {"L": 0.395, "A": 0.646, "N": 1.0},
		"AC": {"H": 0.35, "M": 0.61, "L": 0.71},
		"Au": {"M": 0.45, "S": 0.56, "N": 0.704},
		"C":  {"N": 0.0, "P": 0.275, "C": 0.66},
		"I":  {"N": 0.0, "P": 0.275, "C": 0.66},
		"A":  {"N": 0.0, "P": 0.275, "C": 0.66},
	}

	av := lookupWeight(metrics, weights, "AV", 0)
	ac := lookupWeight(metrics, weights, "AC", 0)
	auth := lookupWeight(metrics, weights, "Au", 0)
	conf := lookupWeight(metrics, weights, "C", 0)
	integ := lookupWeight(metrics, weights, "I", 0)
	avail := lookupWeight(metrics, weights, "A", 0)
	if av == 0 || ac == 0 || auth == 0 {
		return 0
	}

	impact := 10.41 * (1.0 - (1.0-conf)*(1.0-integ)*(1.0-avail))
	if impact <= 0 {
		return 0
	}
	exploitability := 20.0 * av * ac * auth
	score := ((0.6 * impact) + (0.4 * exploitability) - 1.5) * 1.176
	if score > 10.0 {
		score = 10.0
	}
	if score < 0 {
		score = 0
	}
	return roundNearest1(score)
}

// CVSSToSeverity maps a CVSS base score (0-10) to a severity string
// using the standard NVD ranges.
func CVSSToSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}

func lookupWeight(metrics map[string]string, weights map[string]map[string]float64, key string, fallback float64) float64 {
	val, ok := metrics[key]
	if !ok {
		return fallback
	}
	w, ok := weights[key][val]
	if !ok {
		return fallback
	}
	return w
}

func pow(base float64, exp int) float64 {
	result := 1.0
	for range exp {
		result *= base
	}
	return result
}

func roundUp1(val float64) float64 {
	i := int(val * 10)
	if float64(i)/10.0 < val {
		i++
	}
	return float64(i) / 10.0
}

func roundNearest1(val float64) float64 {
	return float64(int(val*10+0.5)) / 10.0
}
